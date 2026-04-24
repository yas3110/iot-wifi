#ifndef PUFMODULE_H
#define PUFMODULE_H

#include <omnetpp.h>
#include <string>
#include <map>
#include <set>

using namespace omnetpp;

struct CrpChain {
    std::string currentChallenge;
    std::string expectedResponse;
    int usageCount = 0;
};

struct EnrollSession {
    std::string peerId;
    bool iAmInitiator = false;
    std::string myDhPrivate;
    std::string myDhPublic;
    std::string sharedSecret;
    std::string initialChallenge;
};

class PufModule : public cSimpleModule
{
  public:
    // ---- Chaines CRP ----
    std::string pickChallenge(const std::string& peerId);
    std::string pickMask(const std::string& peerId);
    std::string getExpectedResponse(const std::string& peerId);
    // Vérifie uniquement, sans avancer la chaîne
    bool        verifyAndAdvanceChain(const std::string& peerId, const std::string& response);
    // Avance la copie locale de la chaîne d'un peer — appelé par l'initiateur dans authSuccess
    void        advancePeerChain(const std::string& peerId);
    void        advanceOwnChain();

    // ---- Enrôlement Ad Hoc ----
    std::string startEnroll(const std::string& peerId);
    std::string replyEnroll(const std::string& peerId, const std::string& peerDhPublic);
    void        finalizeEnroll(const std::string& peerId,
                               const std::string& peerDhPublic,
                               const std::string& peerInitialChallenge,
                               const std::string& peerInitialResponse);
    std::string getMyDhPublic(const std::string& peerId);

    // ---- PUF / Crypto ----
    std::string computeResponse(const std::string& challenge);
    std::string verifyGetResponse(const std::string& peerId, const std::string& challenge);
    std::string applyMask(const std::string& response, const std::string& mask);
    std::string computeKtemp(const std::string& nA, const std::string& nB);
    std::string computeKAB(const std::string& rA, const std::string& rB,
                           const std::string& bA, const std::string& bB,
                           const std::string& nA, const std::string& nB);
    std::string computeMAC(const std::string& key, const std::string& data);
    std::string xorEncrypt(const std::string& key, const std::string& data);
    std::string xorDecrypt(const std::string& key, const std::string& hexData);
    std::string generateNonce();
    std::string getFingerprint();
    std::string sha256hex(const std::string& input);

    // ---- Relations / Trust ----
    int    getAuthLevel(const std::string& peerId);
    void   updateTrustScore(const std::string& peerId, bool success);
    double getTrustScore(const std::string& peerId);
    bool   isBlocked(const std::string& peerId);
    bool   isPeerKnown(const std::string& peerId);
    void   setRelation(const std::string& peerId, const std::string& rel);
    void   addAdHocPeer(const std::string& peerId, const std::string& sharedSecret);
    void   loadPeerCrpDb(const std::string& peerId,
                         const std::map<std::string,std::string>& db);
    void   initChainForPeer(const std::string& peerId,
                            const std::string& seedChallenge,
                            const std::string& seedResponse);

    const std::map<std::string,std::string>& getRelationMap() const { return relationType; }

  protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage* msg) override;

  private:
    std::string computeOwnResponse(const std::string& challenge);
    std::string deriveNextChallenge(const std::string& current);
    std::string deriveNextResponse(const std::string& currentResponse,
                                   const std::string& nextChallenge);
    std::string computeSharedSecret(const std::string& pubA, const std::string& pubB);

    long pufSeed = 0;
    std::string ownCurrentChallenge;
    std::map<std::string,std::string> own_crp_db;

    std::map<std::string, CrpChain>      peerChains;
    std::map<std::string, EnrollSession> enrollSessions;
    std::map<std::string, std::map<std::string,std::string>> known_crp_dbs;

    std::map<std::string,std::string> relationType;
    std::map<std::string,double>      trustScores;

    double battery    = 0.9;
    double reputation = 0.8;
    int    services   = 3;
    double uptime     = 0.95;

    static constexpr double BLOCK_THRESHOLD = 0.3;
};

#endif
