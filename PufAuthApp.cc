#include "PufAuthApp.h"

Define_Module(PufAuthApp);

void PufAuthApp::initialize()
{
    myId = getParentModule()->getFullName();
    puf  = check_and_cast<PufModule*>(
               getParentModule()->getSubmodule("puf"));
    authInterval         = par("authInterval").doubleValue();
    double authStartTime = par("authStartTime").doubleValue();

    authTimer = new cMessage("authTimer");
    scheduleAt(simTime() + authStartTime, authTimer);
    EV << "[AUTH] " << myId << " initialise (DARPA 4 rounds)." << endl;
}

void PufAuthApp::handleMessage(cMessage* msg)
{
    if (msg == authTimer) {
        EV << "[AUTH] " << myId << " cycle t=" << simTime() << endl;
        scheduleAt(simTime() + authInterval, authTimer);
        for (auto& [peerId, rel] : puf->getRelationMap()) {
            if (sessions.find(peerId) == sessions.end())
                startAuth(peerId);
        }
        return;
    }
    if      (auto* m = dynamic_cast<DarpaRound1*>(msg)) handleRound1(m);
    else if (auto* m = dynamic_cast<DarpaRound2*>(msg)) handleRound2(m);
    else if (auto* m = dynamic_cast<DarpaRound3*>(msg)) handleRound3(m);
    else if (auto* m = dynamic_cast<DarpaRound4*>(msg)) handleRound4(m);
    delete msg;
}

void PufAuthApp::startAuth(const std::string& peerId)
{
    if (puf->getAuthLevel(peerId) == 0) {
        EV << "[AUTH] " << myId << " ignore " << peerId << " (non autorise)" << endl;
        return;
    }

    // FIX COLLISION : seul le noeud avec le hash le plus petit initie
    // pour eviter deux sessions symetriques simultanees sur la meme cle
    std::hash<std::string> hasher;
    size_t myHash   = hasher(myId);
    size_t peerHash = hasher(peerId);
    bool iAmInitiator = (myHash < peerHash) || (myHash == peerHash && myId < peerId);
    if (!iAmInitiator) {
        EV << "[AUTH] " << myId << " laisse " << peerId << " initier" << endl;
        return;
    }

    DarpaSession s;
    s.peerId        = peerId;
    s.initiator     = true;
    s.authLevel     = puf->getAuthLevel(peerId);
    s.nonce_A       = puf->generateNonce();
    s.challenge_iA  = puf->pickChallenge(peerId);  // challenge du PUF de B
    s.mask_iA       = puf->pickMask(peerId);
    s.fingerprint_A = puf->getFingerprint();
    if (s.challenge_iA.empty()) {
        EV_WARN << "[AUTH] Plus de CRP pour " << peerId << endl;
        return;
    }
    sessions[peerId] = s;

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
    if (puf->getAuthLevel(senderId) == 0) {
        EV << "[AUTH] " << myId << " refuse Round1 de " << senderId << endl;
        return;
    }
    // Securite : ignorer si on est deja initiateur vers ce peer
    if (sessions.count(senderId) && sessions[senderId].initiator) {
        EV_WARN << "[AUTH] " << myId << " ignore Round1 de " << senderId
                << " (deja initiateur)" << endl;
        return;
    }

    DarpaSession s;
    s.peerId        = senderId;
    s.initiator     = false;
    s.nonce_A       = msg->getNonce_A();
    s.challenge_iA  = msg->getChallenge();   // challenge du PUF de B (nous)
    s.mask_iA       = msg->getBitMask();
    s.fingerprint_A = msg->getServiceCard();
    s.nonce_B       = puf->generateNonce();
    s.challenge_iB  = puf->pickChallenge(senderId);  // challenge du PUF de A
    s.mask_iB       = puf->pickMask(senderId);
    s.fingerprint_B = puf->getFingerprint();
    if (s.challenge_iB.empty()) {
        EV_WARN << "[AUTH] Plus de CRP pour " << senderId << " (R1)" << endl;
        return;
    }

    // B repond a challenge_iA avec son propre PUF (own_crp_db)
    std::string rawB     = puf->computeResponse(s.challenge_iA);
    s.R_iA_trunc         = puf->applyMask(rawB, s.mask_iA);
    s.K_temp             = puf->computeKtemp(s.nonce_A, s.nonce_B);
    // B connait la reponse attendue de A au challenge_iB (known_crp_dbs)
    std::string R_iB_raw = puf->verifyGetResponse(senderId, s.challenge_iB);
    s.R_iB_trunc         = puf->applyMask(R_iB_raw, s.mask_iB);
    std::string E_iB     = puf->xorEncrypt(s.K_temp, s.R_iB_trunc);
    sessions[senderId]   = s;

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
    if (sessions.find(senderId) == sessions.end()) {
        EV_WARN << "[AUTH] Round2 sans session de " << senderId << endl;
        return;
    }
    auto& s = sessions[senderId];
    s.nonce_B       = msg->getNonce_B();
    s.challenge_iB  = msg->getChallenge();
    s.mask_iB       = msg->getBitMask();
    s.fingerprint_B = msg->getServiceCard();
    s.K_temp        = puf->computeKtemp(s.nonce_A, s.nonce_B);

    // FIX PROOF : A verifie proofBA = applyMask(PUF_B(challenge_iA), mask_iA)
    // challenge_iA est un challenge du PUF de B -> A le cherche dans known_crp_dbs
    std::string expectedProof = puf->applyMask(
        puf->verifyGetResponse(senderId, s.challenge_iA), s.mask_iA);
    if (std::string(msg->getProofBA()) != expectedProof) {
        EV << "[AUTH] ROUND2 preuve B invalide -> ECHEC" << endl;
        authFailed(senderId); return;
    }

    // FIX DECRYPT : utiliser xorDecrypt (inverse de xorEncrypt)
    s.R_iB_trunc = puf->xorDecrypt(s.K_temp,
                       std::string(msg->getEncryptedResponse()));
    s.R_iA_trunc = expectedProof;

    // A repond au challenge_iB avec son propre PUF
    std::string R_iB_seen = puf->applyMask(
        puf->computeResponse(s.challenge_iB), s.mask_iB);
    std::string E_iA = puf->xorEncrypt(s.K_temp, s.R_iA_trunc);
    s.K_AB = puf->computeKAB(s.R_iA_trunc, s.R_iB_trunc,
                 s.fingerprint_A, s.fingerprint_B,
                 s.nonce_A, s.nonce_B);
    std::string tokA = puf->computeMAC(s.K_AB,
                           s.nonce_A + s.nonce_B + myId);

    auto* m = new DarpaRound3("DarpaRound3");
    m->setSenderId(myId.c_str());
    m->setTargetId(senderId.c_str());
    m->setEncryptedResponse(E_iA.c_str());
    m->setProofAB(R_iB_seen.c_str());
    m->setTokenA(tokA.c_str());
    EV << "[AUTH] " << myId << " ROUND3 -> " << senderId << endl;
    sendToPeer(m, senderId);
}

void PufAuthApp::handleRound3(DarpaRound3* msg)
{
    std::string senderId = msg->getSenderId();
    if (sessions.find(senderId) == sessions.end()) {
        EV_WARN << "[AUTH] Round3 sans session de " << senderId << endl;
        return;
    }
    auto& s = sessions[senderId];

    // FIX DECRYPT : utiliser xorDecrypt
    s.R_iA_trunc = puf->xorDecrypt(s.K_temp,
                       std::string(msg->getEncryptedResponse()));

    if (std::string(msg->getProofAB()) != s.R_iB_trunc) {
        EV << "[AUTH] ROUND3 preuve A invalide -> ECHEC" << endl;
        authFailed(senderId); return;
    }
    s.K_AB = puf->computeKAB(s.R_iA_trunc, s.R_iB_trunc,
                 s.fingerprint_A, s.fingerprint_B,
                 s.nonce_A, s.nonce_B);
    std::string expectedTokA = puf->computeMAC(s.K_AB,
                                   s.nonce_A + s.nonce_B + senderId);
    if (std::string(msg->getTokenA()) != expectedTokA) {
        EV << "[AUTH] tok_A invalide -> ECHEC" << endl;
        authFailed(senderId); return;
    }
    authSuccess(senderId, s.K_AB);
    std::string tokB = puf->computeMAC(s.K_AB,
                           s.nonce_B + s.nonce_A + myId);
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
    if (sessions.find(senderId) == sessions.end()) {
        EV_WARN << "[AUTH] Round4 sans session de " << senderId << endl;
        return;
    }
    auto& s = sessions[senderId];
    std::string expectedTokB = puf->computeMAC(s.K_AB,
                                   s.nonce_B + s.nonce_A + senderId);
    if (std::string(msg->getTokenB()) != expectedTokB) {
        EV << "[AUTH] tok_B invalide -> ECHEC" << endl;
        authFailed(senderId); return;
    }
    authSuccess(senderId, s.K_AB);
}

void PufAuthApp::authSuccess(const std::string& peerId,
                              const std::string& kAB)
{
    puf->updateTrustScore(peerId, true);
    authenticated[peerId] = true;
    sessionKeys[peerId]   = kAB;
    sessions.erase(peerId);
    nbSuccess++;
    EV << "[AUTH] OK " << myId << " <-> " << peerId
       << " trust=" << puf->getTrustScore(peerId)
       << " K_AB=" << kAB.substr(0,16) << "..." << endl;
}

void PufAuthApp::authFailed(const std::string& peerId)
{
    puf->updateTrustScore(peerId, false);
    authenticated[peerId] = false;
    sessions.erase(peerId);
    nbFailed++;
    EV << "[AUTH] ECHEC " << myId << " <-> " << peerId
       << " trust=" << puf->getTrustScore(peerId) << endl;
}

void PufAuthApp::sendToPeer(cMessage* msg, const std::string& peerId)
{
    std::string baseName = peerId;
    int index = -1;
    size_t lb = peerId.find('[');
    size_t rb = peerId.find(']');
    if (lb != std::string::npos && rb != std::string::npos) {
        baseName = peerId.substr(0, lb);
        index    = std::stoi(peerId.substr(lb + 1, rb - lb - 1));
    }
    cModule* network = getParentModule()->getParentModule();
    cModule* peer    = (index >= 0)
        ? network->getSubmodule(baseName.c_str(), index)
        : network->getSubmodule(baseName.c_str());
    if (!peer) {
        std::cerr << "[AUTH] PEER INTROUVABLE: " << peerId << std::endl;
        delete msg; return;
    }
    cModule* app = peer->getSubmodule("pufAuthApp");
    if (!app) {
        std::cerr << "[AUTH] pufAuthApp INTROUVABLE sur " << peerId << std::endl;
        delete msg; return;
    }
    cGate* gate = app->gate("directIn");
    if (!gate) {
        std::cerr << "[AUTH] gate directIn INTROUVABLE sur " << peerId << std::endl;
        delete msg; return;
    }
    sendDirect(msg, gate);
}

void PufAuthApp::finish()
{
    EV << "[AUTH] BILAN " << myId
       << " succes=" << nbSuccess
       << " echecs=" << nbFailed << endl;
    recordScalar("puf_auth_success", nbSuccess);
    recordScalar("puf_auth_failed",  nbFailed);
}
