#ifndef PUFMODULE_H
#define PUFMODULE_H

#include <omnetpp.h>
#include <string>
#include <map>
#include <sstream>
#include <iomanip>

using namespace omnetpp;

class PufModule : public cSimpleModule
{
  private:
    std::map<std::string,std::string> own_crp_db;
    std::map<std::string, std::map<std::string,std::string>> known_crp_dbs;
    std::map<std::string,double>      trustScores;
    std::map<std::string,std::string> relationType;
    double battery    = 0.9;
    double reputation = 0.8;
    int    services   = 3;
    double uptime     = 0.95;
    double BLOCK_THRESHOLD = 0.30;
    long pufSeed = 0;

  public:
    std::string computeResponse(const std::string& challenge);
    std::string applyMask(const std::string& response,
                          const std::string& mask);
    bool verifyResponse(const std::string& peerId,
                        const std::string& challenge,
                        const std::string& response);
    std::string verifyGetResponse(const std::string& peerId,
                                  const std::string& challenge);
    int    getAuthLevel(const std::string& peerId);
    void   updateTrustScore(const std::string& peerId, bool success);
    double getTrustScore(const std::string& peerId);
    bool   isBlocked(const std::string& peerId);
    void   loadPeerCrpDb(const std::string& peerId,
                         const std::map<std::string,std::string>& db);
    void   setRelation(const std::string& peerId, const std::string& rel);
    std::string pickChallenge(const std::string& peerId);
    std::string pickMask(const std::string& peerId);
    std::string generateNonce();
    std::string computeKtemp(const std::string& nA, const std::string& nB);
    std::string xorEncrypt(const std::string& key, const std::string& data);
    std::string xorDecrypt(const std::string& key, const std::string& hexData);
    std::string computeKAB(const std::string& rA, const std::string& rB,
                           const std::string& bA, const std::string& bB,
                           const std::string& nA, const std::string& nB);
    std::string computeMAC(const std::string& key, const std::string& data);
    std::string getFingerprint();

    const std::map<std::string,std::string>& getRelationMap() const {
        return relationType;
    }

  protected:
    virtual void initialize()    override;
    virtual void handleMessage(cMessage* msg) override;

  private:
    std::string sha256hex(const std::string& input);
};

#endif
