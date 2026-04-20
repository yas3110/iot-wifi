#include "PufModule.h"
#include "json.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <functional>
#include <random>
#include <openssl/sha.h>
#include <openssl/hmac.h>

using json = nlohmann::json;
Define_Module(PufModule);

// ---------------------------------------------------------------
// INITIALISATION
// ---------------------------------------------------------------
void PufModule::initialize()
{
    std::string nodeId = std::string(getParentModule()->getName())
        + (getParentModule()->isVector()
           ? "[" + std::to_string(getParentModule()->getIndex()) + "]"
           : "");

    // DEBUG — visible même sans EV
    std::cerr << "[PUF-DEBUG] nodeId='" << nodeId << "'" << std::endl;

    pufSeed = (long)std::hash<std::string>{}(nodeId) % 1000000000L;

    std::ifstream f("social_graph.json");
    std::cerr << "[PUF-DEBUG] json ouvert=" << (f.is_open() ? "OUI" : "NON") << std::endl;
    if (!f.is_open()) {
        EV_WARN << "[PUF] social_graph.json introuvable !" << endl;
        return;
    }

    json graph;
    f >> graph;

    std::cerr << "[PUF-DEBUG] nodeId dans graph=" << (graph.contains(nodeId) ? "OUI" : "NON") << std::endl;
    if (!graph.contains(nodeId)) {
        EV_WARN << "[PUF] " << nodeId << " absent du graphe social." << endl;
        return;
    }

    auto& node = graph[nodeId];

    if (node.contains("puf") && node["puf"].contains("crp_db"))
        for (auto& [ch, resp] : node["puf"]["crp_db"].items())
            own_crp_db[ch] = resp.get<std::string>();

    if (node.contains("relations")) {
        if (node["relations"].contains("SOR"))
            for (auto& p : node["relations"]["SOR"])
                setRelation(p.get<std::string>(), "SOR");
        if (node["relations"].contains("OOR"))
            for (auto& p : node["relations"]["OOR"])
                setRelation(p.get<std::string>(), "OOR");
    }

    if (node.contains("known_crp_dbs"))
        for (auto& [peerId, db] : node["known_crp_dbs"].items()) {
            std::map<std::string,std::string> crpMap;
            for (auto& [ch, resp] : db.items())
                crpMap[ch] = resp.get<std::string>();
            loadPeerCrpDb(peerId, crpMap);
        }

    if (node.contains("fingerprint")) {
        battery    = node["fingerprint"].value("battery",    0.9);
        reputation = node["fingerprint"].value("reputation", 0.8);
        services   = node["fingerprint"].value("services",   3);
        uptime     = node["fingerprint"].value("uptime",     0.95);
    }

    if (node.contains("trust_score"))
        trustScores["__self__"] = node["trust_score"].get<double>();

    std::cerr << "[PUF-DEBUG] relations=" << relationType.size()
              << " crpdbs=" << known_crp_dbs.size() << std::endl;

    EV << "[PUF] " << nodeId << " charge : "
       << relationType.size() << " pairs, "
       << own_crp_db.size()   << " own CRP, "
       << known_crp_dbs.size()<< " crp_dbs." << endl;
}
void PufModule::handleMessage(cMessage* msg) { delete msg; }

// ---------------------------------------------------------------
// HASH SHA256
// ---------------------------------------------------------------
std::string PufModule::sha256hex(const std::string& input)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()),
           input.size(), hash);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)hash[i];
    return ss.str();
}

// ---------------------------------------------------------------
// PUF DE BASE
// ---------------------------------------------------------------
std::string PufModule::computeResponse(const std::string& challenge)
{
    auto it = own_crp_db.find(challenge);
    if (it != own_crp_db.end()) return it->second;
    EV_WARN << "[PUF] computeResponse : challenge inconnu : " << challenge << endl;
    return "";
}

std::string PufModule::applyMask(const std::string& response,
                                  const std::string& mask)
{
    // Hash response+mask pour garantir un résultat hex pur (pas de \0 possible)
    // Reproduit le même résultat des deux côtés si response et mask sont identiques
    return sha256hex(response + mask).substr(0, response.size());
}

bool PufModule::verifyResponse(const std::string& peerId,
                                const std::string& challenge,
                                const std::string& response)
{
    if (known_crp_dbs.find(peerId) == known_crp_dbs.end()) {
        EV_WARN << "[PUF] Pas de crp_db pour " << peerId << endl;
        return false;
    }
    auto& db = known_crp_dbs[peerId];
    if (db.find(challenge) == db.end()) {
        EV_WARN << "[PUF] Challenge inconnu pour " << peerId << endl;
        return false;
    }
    bool match = (db[challenge] == response);
    if (match) db.erase(challenge);
    return match;
}

// ---------------------------------------------------------------
// NOUVEAU : retourne la réponse attendue SANS effacer le CRP
// Utilisé par B pour connaître R_iB sans consommer le CRP
// ---------------------------------------------------------------
std::string PufModule::verifyGetResponse(const std::string& peerId,
                                          const std::string& challenge)
{
    auto it = known_crp_dbs.find(peerId);
    if (it == known_crp_dbs.end()) {
        EV_WARN << "[PUF] verifyGetResponse : pas de crp_db pour "
                << peerId << endl;
        return "";
    }
    auto it2 = it->second.find(challenge);
    if (it2 == it->second.end()) {
        EV_WARN << "[PUF] verifyGetResponse : challenge inconnu pour "
                << peerId << " : " << challenge << endl;
        return "";
    }
    return it2->second;  // retourne sans effacer
}

int PufModule::getAuthLevel(const std::string& peerId)
{
    if (isBlocked(peerId)) return 0;
    auto it = relationType.find(peerId);
    if (it == relationType.end()) return 0;
    if (it->second == "SOR") return 1;
    if (it->second == "OOR") return 3;
    return 0;
}

void PufModule::updateTrustScore(const std::string& peerId, bool success)
{
    if (trustScores.find(peerId) == trustScores.end())
        trustScores[peerId] = 0.7;
    double delta = success ? +0.05 : -0.20;
    trustScores[peerId] = std::min(1.0,
                          std::max(0.0, trustScores[peerId] + delta));
    EV << "[PUF] trust(" << peerId << ") = " << trustScores[peerId]
       << (isBlocked(peerId) ? " BLOQUE" : "") << endl;
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

void PufModule::loadPeerCrpDb(const std::string& peerId,
                               const std::map<std::string,std::string>& db)
{
    known_crp_dbs[peerId] = db;
}

void PufModule::setRelation(const std::string& peerId,
                             const std::string& rel)
{
    relationType[peerId] = rel;
}

std::string PufModule::pickChallenge(const std::string& peerId)
{
    auto it = known_crp_dbs.find(peerId);
    if (it == known_crp_dbs.end() || it->second.empty()) return "";
    return it->second.begin()->first;
}

std::string PufModule::pickMask(const std::string& peerId)
{
    return sha256hex(peerId + "mask").substr(0, 16);
}

// ---------------------------------------------------------------
// CRYPTO DARPA
// ---------------------------------------------------------------
std::string PufModule::generateNonce()
{
    std::mt19937_64 rng(std::random_device{}());
    std::stringstream ss;
    for (int i = 0; i < 4; i++)
        ss << std::hex << std::setfill('0')
           << std::setw(16) << rng();
    return ss.str();
}

std::string PufModule::computeKtemp(const std::string& nA,
                                     const std::string& nB)
{
    return sha256hex(nA + nB);
}

std::string PufModule::xorEncrypt(const std::string& key,
                                   const std::string& data)
{
    std::string keyStream = sha256hex(key);
    // XOR puis encodage hex pour éviter les \0 dans les strings C passées via c_str()
    std::stringstream ss;
    for (size_t i = 0; i < data.size(); i++) {
        unsigned char c = (unsigned char)data[i] ^ (unsigned char)keyStream[i % keyStream.size()];
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)c;
    }
    return ss.str();
}

std::string PufModule::xorDecrypt(const std::string& key,
                                   const std::string& hexData)
{
    // Décoder le hex puis XOR (inverse de xorEncrypt)
    std::string keyStream = sha256hex(key);
    std::string result;
    for (size_t i = 0; i + 1 < hexData.size(); i += 2) {
        unsigned char c = (unsigned char)std::stoi(hexData.substr(i, 2), nullptr, 16);
        c ^= (unsigned char)keyStream[(i / 2) % keyStream.size()];
        result += (char)c;
    }
    return result;
}

std::string PufModule::computeKAB(const std::string& rA,
                                   const std::string& rB,
                                   const std::string& bA,
                                   const std::string& bB,
                                   const std::string& nA,
                                   const std::string& nB)
{
    return sha256hex(rA + rB + bA + bB + nA + nB);
}

std::string PufModule::computeMAC(const std::string& key,
                                   const std::string& data)
{
    return sha256hex(key + data).substr(0, 32);
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
