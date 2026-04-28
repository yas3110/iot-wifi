#include "PufModule.h"
#include "json.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <functional>
#include <random>
#include <openssl/sha.h>

using json = nlohmann::json;
Define_Module(PufModule);

void PufModule::initialize()
{
    std::string nodeId = std::string(getParentModule()->getName())
        + (getParentModule()->isVector()
           ? "[" + std::to_string(getParentModule()->getIndex()) + "]"
           : "");

    std::cerr << "[PUF-DEBUG] nodeId='" << nodeId << "'" << std::endl;

    pufSeed = (long)std::hash<std::string>{}(nodeId) % 1000000000L;
    ownCurrentChallenge = sha256hex(nodeId + std::to_string(pufSeed) + "OWN_SEED");

    std::ifstream f("social_graph.json");
    if (!f.is_open()) {
        EV_WARN << "[PUF] social_graph.json introuvable." << endl;
        return;
    }
    json graph;
    f >> graph;

    if (!graph.contains(nodeId)) {
        EV_WARN << "[PUF] " << nodeId << " absent du graphe." << endl;
        return;
    }
    auto& node = graph[nodeId];

    if (node.contains("puf") && node["puf"].contains("crp_db"))
        for (auto& [ch, resp] : node["puf"]["crp_db"].items())
            own_crp_db[ch] = resp.get<std::string>();

    if (node.contains("puf")) {
        auto& pufNode = node["puf"];
        std::string sc = pufNode.value("seed_challenge", "");
        std::string sr = pufNode.value("seed_response",  "");
        if (!sc.empty()) {
            ownCurrentChallenge = sc;
            own_crp_db[sc] = sr;
        }
    }

    if (node.contains("relations")) {
        for (const std::string& type : {"SOR", "OOR"})
            if (node["relations"].contains(type))
                for (auto& p : node["relations"][type])
                    setRelation(p.get<std::string>(), type);
    }

    if (node.contains("known_crp_dbs")) {
        for (auto& [peerId, db] : node["known_crp_dbs"].items()) {
            if (db.is_object() && db.contains("seed_challenge")) {
                std::string sc = db["seed_challenge"].get<std::string>();
                std::string sr = db["seed_response"].get<std::string>();
                initChainForPeer(peerId, sc, sr);
            } else if (db.is_object()) {
                std::map<std::string,std::string> crpMap;
                for (auto& [ch, resp] : db.items())
                    crpMap[ch] = resp.get<std::string>();
                loadPeerCrpDb(peerId, crpMap);
                if (!crpMap.empty()) {
                    auto first = crpMap.begin();
                    initChainForPeer(peerId, first->first, first->second);
                }
            }
        }
    }

    if (node.contains("fingerprint")) {
        battery    = node["fingerprint"].value("battery",    0.9);
        reputation = node["fingerprint"].value("reputation", 0.8);
        services   = node["fingerprint"].value("services",   3);
        uptime     = node["fingerprint"].value("uptime",     0.95);
    }

    if (node.contains("trust_score"))
        trustScores["__self__"] = node["trust_score"].get<double>();

    EV << "[PUF] " << nodeId << " pret : "
       << relationType.size() << " pairs, "
       << peerChains.size() << " chaines." << endl;
}

void PufModule::handleMessage(cMessage* msg) { delete msg; }

// ---------------------------------------------------------------
// CRYPTO
// ---------------------------------------------------------------
std::string PufModule::sha256hex(const std::string& input)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)hash[i];
    return ss.str();
}

std::string PufModule::deriveNextChallenge(const std::string& current)
{
    return sha256hex(current + "DERIVE");
}

std::string PufModule::deriveNextResponse(const std::string& currentResponse,
                                           const std::string& nextChallenge)
{
    return sha256hex(currentResponse + nextChallenge + "CHAIN").substr(0, 16);
}

std::string PufModule::computeOwnResponse(const std::string& challenge)
{
    auto it = own_crp_db.find(challenge);
    if (it != own_crp_db.end()) return it->second;
    return sha256hex(challenge + std::to_string(pufSeed) + "PUF_RESPONSE").substr(0, 16);
}

std::string PufModule::computeResponse(const std::string& challenge)
{
    return computeOwnResponse(challenge);
}

// ---------------------------------------------------------------
// GESTION DES CHAINES
// ---------------------------------------------------------------
void PufModule::initChainForPeer(const std::string& peerId,
                                  const std::string& seedChallenge,
                                  const std::string& seedResponse)
{
    CrpChain chain;
    chain.currentChallenge = seedChallenge;
    auto dbIt = known_crp_dbs.find(peerId);
    if (dbIt != known_crp_dbs.end() && dbIt->second.count(seedChallenge))
        chain.expectedResponse = dbIt->second.at(seedChallenge);
    else
        chain.expectedResponse = seedResponse;
    chain.usageCount = 0;
    peerChains[peerId] = chain;
}

std::string PufModule::pickChallenge(const std::string& peerId)
{
    auto it = peerChains.find(peerId);
    if (it != peerChains.end())
        return it->second.currentChallenge;
    auto it2 = known_crp_dbs.find(peerId);
    if (it2 != known_crp_dbs.end() && !it2->second.empty())
        return it2->second.begin()->first;
    return "";
}

std::string PufModule::pickMask(const std::string& peerId)
{
    if (peerChains.count(peerId))
        return sha256hex(peerChains[peerId].currentChallenge + "MASK").substr(0, 16);
    return sha256hex(peerId + "mask").substr(0, 16);
}

std::string PufModule::getExpectedResponse(const std::string& peerId)
{
    auto it = peerChains.find(peerId);
    if (it != peerChains.end())
        return it->second.expectedResponse;
    return "";
}

std::string PufModule::verifyGetResponse(const std::string& peerId,
                                          const std::string& challenge)
{
    auto dbIt = known_crp_dbs.find(peerId);
    if (dbIt != known_crp_dbs.end()) {
        auto r = dbIt->second.find(challenge);
        if (r != dbIt->second.end()) return r->second;
    }
    auto it = peerChains.find(peerId);
    if (it != peerChains.end())
        return it->second.expectedResponse;
    return "";
}

bool PufModule::verifyAndAdvanceChain(const std::string& peerId,
                                       const std::string& response)
{
    auto it = peerChains.find(peerId);
    if (it == peerChains.end()) return false;
    return (it->second.expectedResponse == response);
}

void PufModule::advancePeerChain(const std::string& peerId)
{
    auto it = peerChains.find(peerId);
    if (it == peerChains.end()) return;
    CrpChain& chain = it->second;

    std::string nextCh = deriveNextChallenge(chain.currentChallenge);
    auto dbIt = known_crp_dbs.find(peerId);
    if (dbIt != known_crp_dbs.end() && dbIt->second.count(nextCh)) {
        chain.currentChallenge = nextCh;
        chain.expectedResponse = dbIt->second.at(nextCh);
        chain.usageCount++;
    } else {
        EV_WARN << "[PUF-CHAIN] DB épuisée pour " << peerId << ", reste sur C_"
                << chain.usageCount << endl;
    }
}

void PufModule::advanceOwnChain()
{
    ownCurrentChallenge = deriveNextChallenge(ownCurrentChallenge);
}

// ---------------------------------------------------------------
// ENROLMENT AD HOC (CORRIGÉ !)
// ---------------------------------------------------------------
std::string PufModule::computeSharedSecret(const std::string& pubA,
                                            const std::string& pubB)
{
    std::string lo = (pubA < pubB) ? pubA : pubB;
    std::string hi = (pubA < pubB) ? pubB : pubA;
    return sha256hex(lo + hi + "DH_SHARED");
}

std::string PufModule::startEnroll(const std::string& peerId)
{
    EnrollSession s;
    s.peerId       = peerId;
    s.iAmInitiator = true;
    s.myDhPrivate  = generateNonce();
    s.myDhPublic   = sha256hex(s.myDhPrivate + "DH_PUB" + peerId);
    enrollSessions[peerId] = s;
    return s.myDhPublic;
}

std::string PufModule::replyEnroll(const std::string& peerId,
                                    const std::string& peerDhPublic)
{
    EnrollSession s;
    s.peerId       = peerId;
    s.iAmInitiator = false;
    s.myDhPrivate  = generateNonce();
    s.myDhPublic   = sha256hex(s.myDhPrivate + "DH_PUB" + peerId);
    s.sharedSecret = computeSharedSecret(peerDhPublic, s.myDhPublic);
    s.initialChallenge = sha256hex(s.sharedSecret + "INIT_C");
    enrollSessions[peerId] = s;

    // FIX : Générer une vraie base de données de secours pour cet inconnu
    std::map<std::string, std::string> adHocDb;
    std::string currC = s.initialChallenge;
    for (int i = 0; i < 15; i++) {
        std::string currR = sha256hex(currC + s.sharedSecret + "INIT_R").substr(0, 16);
        adHocDb[currC] = currR;
        own_crp_db[currC] = currR; // On sauvegarde pour ne plus échouer lors du Round 1 !
        currC = deriveNextChallenge(currC);
    }

    loadPeerCrpDb(peerId, adHocDb);
    initChainForPeer(peerId, s.initialChallenge, adHocDb[s.initialChallenge]);
    addAdHocPeer(peerId, s.sharedSecret);

    return s.myDhPublic;
}

void PufModule::finalizeEnroll(const std::string& peerId,
                                const std::string& peerDhPublic,
                                const std::string&,
                                const std::string&)
{
    auto it = enrollSessions.find(peerId);
    if (it == enrollSessions.end()) return;
    EnrollSession& s = it->second;
    s.sharedSecret     = computeSharedSecret(s.myDhPublic, peerDhPublic);
    s.initialChallenge = sha256hex(s.sharedSecret + "INIT_C");

    // FIX : Générer une vraie base de données de secours pour cet inconnu
    std::map<std::string, std::string> adHocDb;
    std::string currC = s.initialChallenge;
    for (int i = 0; i < 15; i++) {
        std::string currR = sha256hex(currC + s.sharedSecret + "INIT_R").substr(0, 16);
        adHocDb[currC] = currR;
        own_crp_db[currC] = currR; // On sauvegarde pour ne plus échouer lors du Round 1 !
        currC = deriveNextChallenge(currC);
    }

    loadPeerCrpDb(peerId, adHocDb);
    initChainForPeer(peerId, s.initialChallenge, adHocDb[s.initialChallenge]);
    addAdHocPeer(peerId, s.sharedSecret);

    enrollSessions.erase(peerId);
}

std::string PufModule::getMyDhPublic(const std::string& peerId)
{
    auto it = enrollSessions.find(peerId);
    if (it != enrollSessions.end()) return it->second.myDhPublic;
    return "";
}

// ---------------------------------------------------------------
// RELATIONS ET TRUST
// ---------------------------------------------------------------
void PufModule::addAdHocPeer(const std::string& peerId, const std::string&)
{
    if (!relationType.count(peerId)) relationType[peerId] = "AD_HOC";
    if (!trustScores.count(peerId))  trustScores[peerId]  = 0.50;
}

int PufModule::getAuthLevel(const std::string& peerId)
{
    if (isBlocked(peerId)) return 0;
    auto it = relationType.find(peerId);
    if (it == relationType.end()) return -1;
    if (it->second == "SOR")    return 1;
    if (it->second == "AD_HOC") return 2;
    if (it->second == "OOR")    return 3;
    return 0;
}

void PufModule::updateTrustScore(const std::string& peerId, bool success)
{
    if (!trustScores.count(peerId)) trustScores[peerId] = 0.7;
    double delta = success ? +0.05 : -0.20;
    trustScores[peerId] = std::min(1.0, std::max(0.0, trustScores[peerId] + delta));
}

double PufModule::getTrustScore(const std::string& peerId)
{
    auto it = trustScores.find(peerId);
    return (it != trustScores.end()) ? it->second : 0.5;
}

bool PufModule::isBlocked(const std::string& peerId)
{
    auto it = trustScores.find(peerId);
    return (it != trustScores.end()) && (it->second < BLOCK_THRESHOLD);
}

bool PufModule::isPeerKnown(const std::string& peerId)
{
    return relationType.count(peerId) > 0;
}

void PufModule::setRelation(const std::string& peerId, const std::string& rel)
{
    relationType[peerId] = rel;
}

void PufModule::loadPeerCrpDb(const std::string& peerId,
                               const std::map<std::string,std::string>& db)
{
    known_crp_dbs[peerId] = db;
}

// ---------------------------------------------------------------
// UTILITAIRES CRYPTO
// ---------------------------------------------------------------
std::string PufModule::generateNonce()
{
    std::mt19937_64 rng(std::random_device{}());
    std::stringstream ss;
    for (int i = 0; i < 4; i++)
        ss << std::hex << std::setfill('0') << std::setw(16) << rng();
    return ss.str();
}

std::string PufModule::applyMask(const std::string& response, const std::string& mask)
{
    return sha256hex(response + mask).substr(0, response.size());
}

std::string PufModule::computeKtemp(const std::string& nA, const std::string& nB)
{
    return sha256hex(nA + nB);
}

std::string PufModule::computeKAB(const std::string& rA, const std::string& rB,
                                   const std::string& bA, const std::string& bB,
                                   const std::string& nA, const std::string& nB)
{
    return sha256hex(rA + rB + bA + bB + nA + nB);
}

std::string PufModule::computeMAC(const std::string& key, const std::string& data)
{
    return sha256hex(key + data).substr(0, 32);
}

std::string PufModule::xorEncrypt(const std::string& key, const std::string& data)
{
    std::string ks = sha256hex(key);
    std::stringstream ss;
    for (size_t i = 0; i < data.size(); i++) {
        unsigned char c = (unsigned char)data[i] ^ (unsigned char)ks[i % ks.size()];
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)c;
    }
    return ss.str();
}

std::string PufModule::xorDecrypt(const std::string& key, const std::string& hexData)
{
    std::string ks = sha256hex(key);
    std::string result;
    for (size_t i = 0; i + 1 < hexData.size(); i += 2) {
        unsigned char c = (unsigned char)std::stoi(hexData.substr(i, 2), nullptr, 16);
        c ^= (unsigned char)ks[(i / 2) % ks.size()];
        result += (char)c;
    }
    return result;
}

std::string PufModule::getFingerprint()
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0')
       << std::setw(4) << (int)(battery    * 1000) % 0xFFFF
       << std::setw(4) << (int)(reputation * 1000) % 0xFFFF
       << std::setw(4) << services % 0xFFFF
       << std::setw(4) << (int)(uptime     * 1000) % 0xFFFF;
    return ss.str();
}

