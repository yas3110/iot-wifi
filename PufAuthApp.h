#ifndef PUFAUTHAPP_H
#define PUFAUTHAPP_H

#include <omnetpp.h>
#include <string>
#include <map>
#include <set>
#include <iostream>
#include "PufModule.h"
#include "PufMessages_m.h"

using namespace omnetpp;

struct DarpaSession {
    std::string peerId;
    bool        initiator;
    int         authLevel;
    std::string nonce_A;
    std::string nonce_B;
    std::string challenge_iA;
    std::string challenge_iB;
    std::string mask_iA;
    std::string mask_iB;
    std::string fingerprint_A;
    std::string fingerprint_B;
    std::string R_iA_trunc;
    std::string R_iB_trunc;
    std::string K_temp;
    std::string K_AB;
};

class PufAuthApp : public cSimpleModule
{
  private:
    PufModule* puf;
    std::string myId;

    std::map<std::string, DarpaSession> sessions;
    std::map<std::string, bool>         authenticated;
    std::map<std::string, std::string>  sessionKeys;
    std::set<std::string>               pendingEnrollments;

    cMessage* authTimer;
    double      authInterval;
    int nbSuccess  = 0;
    int nbFailed   = 0;
    int nbEnrolled = 0;

  protected:
    virtual void initialize()    override;
    virtual void handleMessage(cMessage* msg) override;
    virtual void finish()        override;

  public:
    void startAuth(const std::string& peerId);

  private:
    void scheduleSessionTimeout(const std::string& peerId);

    void handleRound1(DarpaRound1* msg);
    void handleRound2(DarpaRound2* msg);
    void handleRound3(DarpaRound3* msg);
    void handleRound4(DarpaRound4* msg);
    void authSuccess(const std::string& peerId, const std::string& kAB);
    void authFailed(const std::string& peerId);

    void initiateEnroll(const std::string& peerId);
    void handleEnrollRequest(EnrollRequest* msg);
    void handleEnrollReply(EnrollReply* msg);
    void handleEnrollConfirm(EnrollConfirm* msg);

    void sendToPeer(cMessage* msg, const std::string& peerId);
};

#endif
