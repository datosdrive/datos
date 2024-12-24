// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_STORAGE_MANAGER_H
#define BITCOIN_STORAGE_MANAGER_H

#include <consensus/params.h>
#include <serialize.h>
#include <storage/netproof.h>
#include <storage/proof.h>
#include <storage/serialize.h>
#include <storage/util.h>
#include <uint256.h>

#include <cstddef>
#include <list>
#include <type_traits>

class CProofManager;
class CNetworkProof;
extern CProofManager proofManager;
extern std::vector<CNetworkProof> proofs;

static unsigned int MIN_PROOF_SZ = 0;
static unsigned int MIN_NETWORKPROOF_SZ = 0;
static const int MAX_NETWORKPROOF = 128;

class CProofManager {
public:
    int CacheSize() const;
    bool Initialise(const Consensus::Params& params) const;
    bool IsProofRequired(int height, const Consensus::Params& params) const;
    bool AlreadyHave(const uint256& hash) const;
    bool ExistsForHeight(int height) const;
    bool GetProofByHash(const uint256& hash, CNetworkProof& netproof) const;
    bool GetProofByHeight(int height, CNetworkProof& netproof) const;
    bool IsFullProofRequired(int height, CNetworkProof& netproof, const Consensus::Params& params) const;
    bool CheckSig(uint256& hash, std::vector<unsigned char>& vchProofSig, std::string& strError) const;
    bool Validate(CNetworkProof& netproof) const;
};

#endif // BITCOIN_STORAGE_MANAGER_H
