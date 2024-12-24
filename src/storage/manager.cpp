// Copyright (c) 2023 datos
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <storage/manager.h>

#include <chainparams.h>
#include <hash.h>
#include <key_io.h>
#include <logging.h>
#include <protocol.h>
#include <pubkey.h>
#include <streams.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <validation.h>

CProofManager proofManager;
std::vector<CNetworkProof> proofs;

int CProofManager::CacheSize() const
{
    int cache_sz;

    cache_sz = 0;
    for (auto& l : proofs)
        cache_sz++;

    return cache_sz;
}

bool CProofManager::Initialise(const Consensus::Params& params) const
{
    int height;
    CBlockIndex* pindex;

    // this gets populated incidentally during reindex
    if (CacheSize() >= MAX_NETWORKPROOF) {
        LogPrint(BCLog::STORAGE, "%s: proofs cache already populated\n", __func__);
        return true;
    }

    // otherwise do it manually..
    LOCK(cs_main);
    height = ::ChainActive().Height();
    while (CacheSize() < MAX_NETWORKPROOF && (height > params.nLastPoWBlock)) {
        pindex = ::ChainActive()[height];
        proofs.push_back(pindex->netProof);
    }

    return true;
}

bool CProofManager::IsProofRequired(int height, const Consensus::Params& params) const
{
    if (height > params.nLastPoWBlock) {
        return true;
    }

    return false;
}

bool CProofManager::AlreadyHave(const uint256& hash) const
{
    for (auto& l : proofs) {
        if (l.hash == hash) {
            LogPrint(BCLog::STORAGE, "%s: already have netproof hash %s for height %d\n", __func__, l.hash.ToString(), l.height);
            return true;
        }
    }

    return false;
}

bool CProofManager::ExistsForHeight(int height) const
{
    for (auto& l : proofs) {
        if (l.height == height) {
            LogPrint(BCLog::STORAGE, "%s: netproof hash %s exists for height %d\n", __func__, l.hash.ToString(), l.height);
            return true;
        }
    }

    return false;
}

bool CProofManager::GetProofByHash(const uint256& hash, CNetworkProof& netproof) const
{
    for (auto& l : proofs) {
        if (l.hash == hash) {
            netproof = l;
            LogPrint(BCLog::STORAGE, "%s: returning netproof hash %s for height %d\n", __func__, netproof.hash.ToString(), netproof.height);
            return true;
        }
    }

    LogPrint(BCLog::STORAGE, "%s: netproof not found with hash %s\n", __func__, hash.ToString());

    return false;
}

bool CProofManager::GetProofByHeight(int height, CNetworkProof& netproof) const
{
    for (auto& l : proofs) {
        if (l.height == height) {
            netproof = l;
            LogPrint(BCLog::STORAGE, "%s: returning netproof hash %s for height %d\n", __func__, netproof.hash.ToString(), height);
            return true;
        }
    }

    LogPrint(BCLog::STORAGE, "%s: netproof not found for height %d\n", __func__, height);

    return false;
}

bool CProofManager::IsFullProofRequired(int height, CNetworkProof& netproof, const Consensus::Params& params) const
{
    if (height >= params.FullProofHeight) {
        if (netproof.IsEmpty()) {
            LogPrint(BCLog::STORAGE, "%s: netproof hash %s is an empty proof, no longer accepted after height %d\n", __func__, netproof.hash.ToString(), params.FullProofHeight);
            return false;
        }
    }
    return true;
}

bool CProofManager::CheckSig(uint256& hash, std::vector<unsigned char>& vchProofSig, std::string& strError) const
{
    if (vchProofSig.empty()) {
        strError = "proofsig-empty";
        return false;
    }

    const Consensus::Params& params = Params().GetConsensus();
    CTxDestination dest = DecodeDestination(params.proofPublicKey);
    const CKeyID* keyID = boost::get<CKeyID>(&dest);
    if (!keyID) {
        strError = "internal-pubkey-error";
        return false;
    }

    CPubKey pubkey;
    std::string strErrorRet;
    if (!pubkey.RecoverCompact(hash, vchProofSig)) {
        strError = "internal-sighash-error";
        return false;
    }

    if (pubkey.GetID() != *keyID) {
        strError = "internal-pubkey-mismatch";
        return false;
    }

    return true;
}

bool CProofManager::Validate(CNetworkProof& netproof) const
{
    int height = netproof.height;
    const Consensus::Params& params = Params().GetConsensus();

    if (height == 0 || netproof.hash == uint256()) {
        LogPrint(BCLog::STORAGE, "%s: incomplete proof\n", __func__);
        return false;
    }

    if (!IsProofRequired(height, params)) {
        LogPrint(BCLog::STORAGE, "%s: proof not required for height %d\n", __func__, height);
        return true;
    }

    if (AlreadyHave(netproof.hash)) {
        LogPrint(BCLog::STORAGE, "%s: already have proof hash %s\n", __func__, netproof.hash.ToString());
        return true;
    }

    if (!IsFullProofRequired(height, netproof, params)) {
        LogPrint(BCLog::STORAGE, "%s: empty proof where full proof required (height %d, enforced %d)\n", __func__, height, params.FullProofHeight);
        return false;
    }

    std::string strError;
    if (!CheckSig(netproof.hash, netproof.vchProofSig, strError)) {
        LogPrint(BCLog::STORAGE, "%s: invalid netproof (error: %s)\n", __func__, strError);
        return false;
    }

    proofs.push_back(netproof);
    LogPrint(BCLog::STORAGE, "%s: proof accepted for height %d\n", __func__, height);

    return true;
}
