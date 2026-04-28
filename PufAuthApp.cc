#include "PufAuthApp.h"
#include <cstdlib>
#include <vector>
#include <algorithm>

Define_Module(PufAuthApp);

static constexpr double AODV_CONVERGENCE_TIME = 25.0;
static constexpr double SESSION_TIMEOUT = 15.0;

void PufAuthApp::initialize()
{
    myId = getParentModule()->getFullName();
    puf  = check_and_cast<PufModule*>(getParentModule()->getSubmodule("puf"));
    authInterval  = par("authInterval").doubleValue();
    double startT = par("authStartTime").doubleValue();
    authTimer = new cMessage("authTimer");
    
    double jitter = uniform(0.0, 5.0);
    scheduleAt(simTime() + startT + jitter, authTimer);
    EV << "[AUTH] " << myId << " initialise, demarrage a t=" << (startT + jitter) << endl;
}

void PufAuthApp::handleMessage(cMessage* msg)
{
    if (msg->isName("sessionTimeout")) {
        std::string peerId = msg->par("peerId").stringValue();
        if (sessions.count(peerId)) {
            EV << "[AUTH] " << myId << " timeout session avec " << peerId << endl;
            sessions.erase(peerId);
        }
        delete msg;
        return;
    }

    if (msg->isName("enrollTimeout")) {
        std::string peerId = msg->par("peerId").stringValue();
        if (pendingEnrollments.count(peerId) && puf->getAuthLevel(peerId) == -1) {
            EV << "[ENROLL] " << myId << " timeout enrolement " << peerId << endl;
            pendingEnrollments.erase(peerId);
        }
        delete msg;
        return;
    }

    if (msg == authTimer) {
        EV << "[AUTH] " << myId << " cycle t=" << simTime() << endl;

        scheduleAt(simTime() + authInterval + uniform(-2.0, 2.0), authTimer);

        for (auto it = authenticated.begin(); it != authenticated.end(); ) {
            if (!sessions.count(it->first))
                it = authenticated.erase(it);
            else
                ++it;
        }

        std::vector<std::string> candidates;
        for (auto& [peerId, rel] : puf->getRelationMap()) {
            int level = puf->getAuthLevel(peerId);
            if (level > 0 && !sessions.count(peerId) && !authenticated.count(peerId)) {
                candidates.push_back(peerId);
            }
        }

        if (!candidates.empty()) {
            for (size_t i = candidates.size() - 1; i > 0; --i) {
                size_t j = intuniform(0, i);
                std::swap(candidates[i], candidates[j]);
            }

            int concurrentAuths = 0;
            for (const std::string& peerId : candidates) {
                startAuth(peerId);
                concurrentAuths++;
                if (concurrentAuths >= 2) break; 
            }
        }

        cModule* network = getParentModule()->getParentModule();
        std::vector<std::string> unknowns;
        for (cModule::SubmoduleIterator it(network); !it.end(); ++it) {
            cModule* peer = *it;
            std::string peerId = peer->getFullName();
            if (peerId == myId) continue;
            if (!peer->getSubmodule("pufAuthApp")) continue;
            if (puf->getAuthLevel(peerId) == -1 && !pendingEnrollments.count(peerId))
                unknowns.push_back(peerId);
        }
        if (!unknowns.empty()) {
            size_t idx = std::hash<std::string>{}(myId + std::to_string((int)simTime().dbl()))
                         % unknowns.size();
            initiateEnroll(unknowns[idx]);
        }
        return;
    }

    if (auto* m = dynamic_cast<DarpaRound1*>(msg))        { handleRound1(m);        delete msg; }
    else if (auto* m = dynamic_cast<DarpaRound2*>(msg))   { handleRound2(m);        delete msg; }
    else if (auto* m = dynamic_cast<DarpaRound3*>(msg))   { handleRound3(m);        delete msg; }
    else if (auto* m = dynamic_cast<DarpaRound4*>(msg))   { handleRound4(m);        delete msg; }
    else if (auto* m = dynamic_cast<EnrollRequest*>(msg)) { handleEnrollRequest(m); delete msg; }
    else if (auto* m = dynamic_cast<EnrollReply*>(msg))   { handleEnrollReply(m);   delete msg; }
    else if (auto* m = dynamic_cast<EnrollConfirm*>(msg)) { handleEnrollConfirm(m); delete msg; }
    else delete msg;
}

void PufAuthApp::scheduleSessionTimeout(const std::string& peerId)
{
    cMessage* t = new cMessage("sessionTimeout");
    t->addPar("peerId") = peerId.c_str();
    scheduleAt(simTime() + SESSION_TIMEOUT, t);
}

void PufAuthApp::startAuth(const std::string& peerId)
{
    if (puf->isBlocked(peerId)) return;

    // ANTI-DOUBLON : Ne pas relancer si une session est déjà en cours
    if (sessions.count(peerId)) return;

    if (puf->getAuthLevel(peerId) <= 0) {
        if (!pendingEnrollments.count(peerId))
            initiateEnroll(peerId);
        return;
    }

    std::string challenge = puf->pickChallenge(peerId);
    if (challenge.empty()) {
        EV_WARN << "[AUTH] Pas de challenge pour " << peerId << endl;
        return;
    }

    DarpaSession s;
    s.peerId        = peerId;
    s.initiator     = true;
    s.authLevel     = puf->getAuthLevel(peerId);
    s.nonce_A       = puf->generateNonce();
    s.challenge_iA  = challenge;
    s.mask_iA       = puf->pickMask(peerId);
    s.fingerprint_A = puf->getFingerprint();
    sessions[peerId] = s;
    scheduleSessionTimeout(peerId);

    auto* m = new DarpaRound1("DarpaRound1");
    m->setSenderId(myId.c_str());
    m->setTargetId(peerId.c_str());
    m->setNonce_A(s.nonce_A.c_str());
    m->setServiceCard(s.fingerprint_A.c_str());
    m->setChallenge(s.challenge_iA.c_str());
    m->setBitMask(s.mask_iA.c_str());
    EV << "[AUTH] " << myId << " ROUND1 -> " << peerId << endl;
    sendToPeer(m, peerId);
}

void PufAuthApp::handleRound1(DarpaRound1* msg)
{
    std::string senderId = msg->getSenderId();

    if (puf->isBlocked(senderId)) return;
    if (puf->getAuthLevel(senderId) <= 0) {
        EV << "[AUTH] " << myId << " refuse Round1 de " << senderId << " (inconnu)" << endl;
        return;
    }

    if (sessions.count(senderId)) {
        if (sessions[senderId].initiator) {
            if (myId < senderId) return;
            sessions.erase(senderId);
        } else {
            // ANTI-DOUBLON : C'est un retry Wi-Fi, on a déjà généré notre session répondeur !
            EV << "[AUTH] Doublon Wi-Fi Round1 ignore pour " << senderId << endl;
            return;
        }
    }

    DarpaSession s;
    s.peerId        = senderId;
    s.initiator     = false;
    s.nonce_A       = msg->getNonce_A();
    s.challenge_iA  = msg->getChallenge();
    s.mask_iA       = msg->getBitMask();
    s.fingerprint_A = msg->getServiceCard();
    s.nonce_B       = puf->generateNonce();
    s.challenge_iB  = puf->pickChallenge(senderId);
    s.mask_iB       = puf->pickMask(senderId);
    s.fingerprint_B = puf->getFingerprint();

    if (s.challenge_iB.empty()) {
        EV_WARN << "[AUTH] Plus de CRP pour " << senderId << endl;
        return;
    }

    std::string rawB = puf->computeResponse(s.challenge_iA);
    s.R_iA_trunc     = puf->applyMask(rawB, s.mask_iA);
    s.K_temp         = puf->computeKtemp(s.nonce_A, s.nonce_B);

    std::string R_iB_raw = puf->verifyGetResponse(senderId, s.challenge_iB);
    s.R_iB_trunc         = puf->applyMask(R_iB_raw, s.mask_iB);
    std::string E_iB     = puf->xorEncrypt(s.K_temp, s.R_iB_trunc);
    sessions[senderId]   = s;
    scheduleSessionTimeout(senderId);

    auto* m = new DarpaRound2("DarpaRound2");
    m->setSenderId(myId.c_str());
    m->setTargetId(senderId.c_str());
    m->setNonce_A(s.nonce_A.c_str());
    m->setNonce_B(s.nonce_B.c_str());
    m->setServiceCard(s.fingerprint_B.c_str());
    m->setChallenge(s.challenge_iB.c_str());
    m->setBitMask(s.mask_iB.c_str());
    m->setEncryptedResponse(E_iB.c_str());
    m->setProofBA(s.R_iA_trunc.c_str());
    EV << "[AUTH] " << myId << " ROUND2 -> " << senderId << endl;
    sendToPeer(m, senderId);
}

void PufAuthApp::handleRound2(DarpaRound2* msg)
{
    std::string senderId = msg->getSenderId();
    if (!sessions.count(senderId)) return;

    auto& s = sessions[senderId];
    s.nonce_B       = msg->getNonce_B();
    s.challenge_iB  = msg->getChallenge();
    s.mask_iB       = msg->getBitMask();
    s.fingerprint_B = msg->getServiceCard();
    s.K_temp        = puf->computeKtemp(s.nonce_A, s.nonce_B);

    std::string expectedProof = puf->applyMask(
        puf->verifyGetResponse(senderId, s.challenge_iA), s.mask_iA);

    if (std::string(msg->getProofBA()) != expectedProof) {
        EV << "[AUTH] ROUND2 preuve B invalide -> ECHEC" << endl;
        authFailed(senderId);
        return;
    }

    s.R_iA_trunc = expectedProof;
    s.R_iB_trunc = puf->xorDecrypt(s.K_temp, std::string(msg->getEncryptedResponse()));

    std::string R_iB_seen = puf->applyMask(
        puf->computeResponse(s.challenge_iB), s.mask_iB);
    s.K_AB = puf->computeKAB(s.R_iA_trunc, s.R_iB_trunc,
                              s.fingerprint_A, s.fingerprint_B,
                              s.nonce_A, s.nonce_B);
    std::string tokA = puf->computeMAC(s.K_AB, s.nonce_A + s.nonce_B + myId);

    auto* m = new DarpaRound3("DarpaRound3");
    m->setSenderId(myId.c_str());
    m->setTargetId(senderId.c_str());
    m->setEncryptedResponse(puf->xorEncrypt(s.K_temp, s.R_iA_trunc).c_str());
    m->setProofAB(R_iB_seen.c_str());
    m->setTokenA(tokA.c_str());
    EV << "[AUTH] " << myId << " ROUND3 -> " << senderId << endl;
    sendToPeer(m, senderId);
}

void PufAuthApp::handleRound3(DarpaRound3* msg)
{
    std::string senderId = msg->getSenderId();
    if (!sessions.count(senderId)) return;

    auto& s = sessions[senderId];
    s.R_iA_trunc = puf->xorDecrypt(s.K_temp, std::string(msg->getEncryptedResponse()));

    if (std::string(msg->getProofAB()) != s.R_iB_trunc) {
        EV << "[AUTH] ROUND3 preuve A invalide -> ECHEC" << endl;
        authFailed(senderId);
        return;
    }

    s.K_AB = puf->computeKAB(s.R_iA_trunc, s.R_iB_trunc,
                              s.fingerprint_A, s.fingerprint_B,
                              s.nonce_A, s.nonce_B);
    std::string expectedTokA = puf->computeMAC(s.K_AB, s.nonce_A + s.nonce_B + senderId);
    if (std::string(msg->getTokenA()) != expectedTokA) {
        EV << "[AUTH] tok_A invalide -> ECHEC" << endl;
        authFailed(senderId);
        return;
    }

    authSuccess(senderId, s.K_AB);

    std::string tokB = puf->computeMAC(s.K_AB, s.nonce_B + s.nonce_A + myId);
    auto* m = new DarpaRound4("DarpaRound4");
    m->setSenderId(myId.c_str());
    m->setTargetId(senderId.c_str());
    m->setTokenB(tokB.c_str());
    EV << "[AUTH] " << myId << " ROUND4 -> " << senderId << endl;
    sendToPeer(m, senderId);
}

void PufAuthApp::handleRound4(DarpaRound4* msg)
{
    std::string senderId = msg->getSenderId();
    if (!sessions.count(senderId)) return;

    auto& s = sessions[senderId];
    std::string expectedTokB = puf->computeMAC(s.K_AB, s.nonce_B + s.nonce_A + senderId);
    if (std::string(msg->getTokenB()) != expectedTokB) {
        EV << "[AUTH] tok_B invalide -> ECHEC" << endl;
        authFailed(senderId);
        return;
    }
    authSuccess(senderId, s.K_AB);
}

void PufAuthApp::authSuccess(const std::string& peerId, const std::string& kAB)
{
    if (sessions.count(peerId) && sessions[peerId].initiator) {
        puf->advancePeerChain(peerId);
    }
    puf->updateTrustScore(peerId, true);
    authenticated[peerId] = true;
    sessionKeys[peerId]   = kAB;
    sessions.erase(peerId);
    nbSuccess++;
}

void PufAuthApp::authFailed(const std::string& peerId)
{
    if (simTime().dbl() > AODV_CONVERGENCE_TIME) {
        puf->updateTrustScore(peerId, false);
    }
    sessions.erase(peerId);
    nbFailed++;
}

void PufAuthApp::initiateEnroll(const std::string& peerId)
{
    pendingEnrollments.insert(peerId);
    std::string myDhPub = puf->startEnroll(peerId);
    auto* m = new EnrollRequest("EnrollRequest");
    m->setSenderId(myId.c_str());
    m->setTargetId(peerId.c_str());
    m->setDhPublic(myDhPub.c_str());
    m->setServiceCard(puf->getFingerprint().c_str());
    sendToPeer(m, peerId);

    cMessage* t = new cMessage("enrollTimeout");
    t->addPar("peerId") = peerId.c_str();
    scheduleAt(simTime() + SESSION_TIMEOUT, t);
}

void PufAuthApp::handleEnrollRequest(EnrollRequest* msg)
{
    std::string senderId = msg->getSenderId();
    if (puf->isBlocked(senderId)) return;

    std::string peerDhPub = msg->getDhPublic();
    std::string myDhPub   = puf->replyEnroll(senderId, peerDhPub);

    std::string initChallenge = puf->pickChallenge(senderId);
    std::string initResp      = puf->verifyGetResponse(senderId, initChallenge);

    auto* m = new EnrollReply("EnrollReply");
    m->setSenderId(myId.c_str());
    m->setTargetId(senderId.c_str());
    m->setDhPublic(myDhPub.c_str());
    m->setServiceCard(puf->getFingerprint().c_str());
    m->setInitialChallenge(initChallenge.c_str());
    m->setInitialResponse(initResp.c_str());
    sendToPeer(m, senderId);
}

void PufAuthApp::handleEnrollReply(EnrollReply* msg)
{
    std::string senderId      = msg->getSenderId();
    std::string peerDhPub     = msg->getDhPublic();
    std::string initChallenge = msg->getInitialChallenge();
    std::string initResp      = msg->getInitialResponse();

    pendingEnrollments.erase(senderId);
    puf->finalizeEnroll(senderId, peerDhPub, initChallenge, initResp);

    std::string pufProof = puf->computeResponse(initChallenge);
    std::string macKey   = puf->sha256hex(initChallenge + senderId + myId + "ENROLL_MAC");
    std::string mac      = puf->computeMAC(macKey, myId + senderId + pufProof);

    auto* m = new EnrollConfirm("EnrollConfirm");
    m->setSenderId(myId.c_str());
    m->setTargetId(senderId.c_str());
    m->setPufProof(pufProof.c_str());
    m->setMac(mac.c_str());
    sendToPeer(m, senderId);
    nbEnrolled++;
}

void PufAuthApp::handleEnrollConfirm(EnrollConfirm* msg)
{
    std::string senderId = msg->getSenderId();
    std::string pufProof = msg->getPufProof();
    std::string expected = puf->getExpectedResponse(senderId);

    if (pufProof == expected) {
        nbEnrolled++;
        if (!sessions.count(senderId))
            startAuth(senderId);
    } else {
        puf->updateTrustScore(senderId, false);
    }
}

void PufAuthApp::sendToPeer(cMessage* msg, const std::string& peerId)
{
    std::string baseName = peerId;
    int index = -1;
    size_t lb = peerId.find('['), rb = peerId.find(']');
    if (lb != std::string::npos && rb != std::string::npos) {
        baseName = peerId.substr(0, lb);
        index    = std::stoi(peerId.substr(lb + 1, rb - lb - 1));
    }
    cModule* network = getParentModule()->getParentModule();
    cModule* peer    = (index >= 0)
        ? network->getSubmodule(baseName.c_str(), index)
        : network->getSubmodule(baseName.c_str());

    if (!peer) { delete msg; return; }
    cModule* app = peer->getSubmodule("pufAuthApp");
    if (!app)  { delete msg; return; }
    cGate* gate = app->gate("directIn");
    if (!gate) { delete msg; return; }
    sendDirect(msg, gate);
}

void PufAuthApp::finish()
{
    EV << "[AUTH] BILAN " << myId
       << " succes="      << nbSuccess
       << " echecs="      << nbFailed
       << " enrolements=" << nbEnrolled << endl;
    recordScalar("puf_auth_success", nbSuccess);
    recordScalar("puf_auth_failed",  nbFailed);
    recordScalar("puf_enroll_adhoc", nbEnrolled);
}
