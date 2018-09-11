// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2013  The Cubits developer
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _BOUNTYCOINALERT_H_
#define _BOUNTYCOINALERT_H_ 1

#include <set>
#include <string>

#include "uint256.h"
#include "util.h"


static const char* pszMainKey = "049c6f81e78ea0a0efbb320f9baea69d61e306cd61bef9cb32673c07088303a58e35b942e6a71b9354c4f927e4f462df948dc833bf69a15b6fc854736693ca87da";

// TestNet alerts pubKey
static const char* pszTestKey = "040171ecaef99d84190e9a2bd58e05d230e6928de59b091f8493c1432cee4dfafa50ad6759de1726314e778bdf4d1b9e91668ff46a6465a5b279c0583c39a4ced9";
// "PrivateKey" : 308201130201010420b1ba399ca41302970143b0b04497bd1199e4a6ec44eab9b33b53021ebd98d2f7a081a53081a2020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f300604010004010704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101a144034200040171ecaef99d84190e9a2bd58e05d230e6928de59b091f8493c1432cee4dfafa50ad6759de1726314e778bdf4d1b9e91668ff46a6465a5b279c0583c39a4ced9


class CNode;

/** Alerts are for notifying old versions if they become too obsolete and
 * need to upgrade.  The message is displayed in the status bar.
 * Alert messages are broadcast as a vector of signed data.  Unserializing may
 * not read the entire buffer if the alert is for a newer version, but older
 * versions can still relay the original data.
 */
class CUnsignedAlert
{
public:
    int nVersion;
    int64 nRelayUntil;      // when newer nodes stop relaying to newer nodes
    int64 nExpiration;
    int nID;
    int nCancel;
    std::set<int> setCancel;
    int nMinVer;            // lowest version inclusive
    int nMaxVer;            // highest version inclusive
    std::set<std::string> setSubVer;  // empty matches all
    int nPriority;

    // Actions
    std::string strComment;
    std::string strStatusBar;
    std::string strReserved;

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(nRelayUntil);
        READWRITE(nExpiration);
        READWRITE(nID);
        READWRITE(nCancel);
        READWRITE(setCancel);
        READWRITE(nMinVer);
        READWRITE(nMaxVer);
        READWRITE(setSubVer);
        READWRITE(nPriority);

        READWRITE(strComment);
        READWRITE(strStatusBar);
        READWRITE(strReserved);
    )

    void SetNull();

    std::string ToString() const;
    void print() const;
};

/** An alert is a combination of a serialized CUnsignedAlert and a signature. */
class CAlert : public CUnsignedAlert
{
public:
    std::vector<unsigned char> vchMsg;
    std::vector<unsigned char> vchSig;

    CAlert()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vchMsg);
        READWRITE(vchSig);
    )

    void SetNull();
    bool IsNull() const;
    uint256 GetHash() const;
    bool IsInEffect() const;
    bool Cancels(const CAlert& alert) const;
    bool AppliesTo(int nVersion, std::string strSubVerIn) const;
    bool AppliesToMe() const;
    bool RelayTo(CNode* pnode) const;
    bool CheckSignature() const;
    bool ProcessAlert();

    /*
     * Get copy of (active) alert object by hash. Returns a null alert if it is not found.
     */
    static CAlert getAlertByHash(const uint256 &hash);
};

#endif
