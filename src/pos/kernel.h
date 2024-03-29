// Copyright (c) 2012-2013 The PPCoin developers
// Copyright (c) 2014 The BlackCoin developers
// Copyright (c) 2017-2021 The Particl Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PARTICL_POS_KERNEL_H
#define PARTICL_POS_KERNEL_H

#include <validation.h>

static const uint32_t nStakeTimestampMask = (1 << 4) - 1;

/**
 * Calculate PoS kernel weight for an interval of prior blocks
 */
double GetPoSKernelPS(CBlockIndex *pindex);

/**
 * Compute the hash modifier for proof-of-stake
 */
uint256 ComputeStakeModifier(const CBlockIndex *pindexPrev, const uint256 &kernel);

/**
 * Check whether stake kernel meets hash target
 * Sets hashProofOfStake on success return
 */
bool CheckStakeKernelHash(const CBlockIndex *pindexPrev,
    uint32_t nBits, uint32_t nBlockFromTime,
    CAmount prevOutAmount, const COutPoint &prevout, uint32_t nTimeTx,
    uint256 &hashProofOfStake, uint256 &targetProofOfStake,
    bool fPrintProofOfStake=false);

/**
 * Get kernel hash and value for blockindex and coinstake tx
 */
bool GetKernelInfo(const CBlockIndex *blockindex, const CTransaction &tx, uint256 &hash, CAmount &value, CScript &script, uint256 &blockhash);

/**
 * Check kernel hash target and coinstake signature
 * Sets hashProofOfStake on success return
 */
bool CheckProofOfStake(CValidationState &state, const CBlockIndex *pindexPrev, const CTransaction &tx, int64_t nTime, unsigned int nBits, uint256 &hashProofOfStake, uint256 &targetProofOfStake, const Consensus::Params& params) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/**
 * Check whether the coinstake timestamp meets protocol
 */
bool CheckCoinStakeTimestamp(int nHeight, int64_t nTimeBlock);

/**
 * Wrapper around CheckStakeKernelHash()
 * Also checks existence of kernel input and min age
 * Convenient for searching a kernel
 */
bool CheckKernel(const CBlockIndex *pindexPrev, unsigned int nBits, int64_t nTime, const COutPoint &prevout, int64_t* pBlockTime = nullptr);

#endif // PARTICL_POS_KERNEL_H
