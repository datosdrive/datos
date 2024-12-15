// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2014-2022 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <llmq/params.h>
#include <tinyformat.h>
#include <util/ranges.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <versionbitsinfo.h>

#include <arith_uint256.h>

#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

static CBlock CreateDevNetGenesisBlock(const uint256 &prevBlockHash, const std::string& devNetName, uint32_t nTime, uint32_t nNonce, uint32_t nBits, const CAmount& genesisReward)
{
    assert(!devNetName.empty());

    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    // put height (BIP34) and devnet name into coinbase
    txNew.vin[0].scriptSig = CScript() << 1 << std::vector<unsigned char>(devNetName.begin(), devNetName.end());
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = CScript() << OP_RETURN;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = 4;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock = prevBlockHash;
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=00000ffd590b14, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=e0028e, nTime=1390095618, nBits=1e0ffff0, nNonce=28917698, vtx=1)
 *   CTransaction(hash=e0028e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d01044c5957697265642030392f4a616e2f3230313420546865204772616e64204578706572696d656e7420476f6573204c6976653a204f76657273746f636b2e636f6d204973204e6f7720416363657074696e6720426974636f696e73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0xA9037BAC7050C479B121CF)
 *   vMerkleTree: e0028e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "datos oct2023 - decentralized masternode storage solution";
    const CScript genesisOutputScript = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

static CBlock FindDevNetGenesisBlock(const CBlock &prevBlock, const CAmount& reward)
{
    std::string devNetName = gArgs.GetDevNetName();
    assert(!devNetName.empty());

    CBlock block = CreateDevNetGenesisBlock(prevBlock.GetHash(), devNetName, prevBlock.nTime + 1, 0, prevBlock.nBits, reward);

    arith_uint256 bnTarget;
    bnTarget.SetCompact(block.nBits);

    for (uint32_t nNonce = 0; nNonce < UINT32_MAX; nNonce++) {
        block.nNonce = nNonce;

        uint256 hash = block.GetHash();
        if (UintToArith256(hash) <= bnTarget)
            return block;
    }

    // This is very unlikely to happen as we start the devnet with a very low difficulty. In many cases even the first
    // iteration of the above loop will give a result already
    error("FindDevNetGenesisBlock: could not find devnet genesis block for %s", devNetName);
    assert(false);
}

void CChainParams::AddLLMQ(Consensus::LLMQType llmqType)
{
    assert(!HasLLMQ(llmqType));
    for (const auto& llmq_param : Consensus::available_llmqs) {
        if (llmq_param.type == llmqType) {
            consensus.llmqs.push_back(llmq_param);
            return;
        }
    }
    error("CChainParams::%s: unknown LLMQ type %d", __func__, static_cast<uint8_t>(llmqType));
    assert(false);
}

const Consensus::LLMQParams& CChainParams::GetLLMQ(Consensus::LLMQType llmqType) const
{
    for (const auto& llmq_param : consensus.llmqs) {
        if (llmq_param.type == llmqType) {
            return llmq_param;
        }
    }
    error("CChainParams::%s: unknown LLMQ type %d", __func__, static_cast<uint8_t>(llmqType));
    assert(false);
}

bool CChainParams::HasLLMQ(Consensus::LLMQType llmqType) const
{
    for (const auto& llmq_param : consensus.llmqs) {
        if (llmq_param.type == llmqType) {
            return true;
        }
    }
    return false;
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = std::numeric_limits<int>::max();
        consensus.nMasternodePaymentsStartBlock = 0;
        consensus.nMasternodePaymentsIncreaseBlock = std::numeric_limits<int>::max();
        consensus.nMasternodePaymentsIncreasePeriod = std::numeric_limits<int>::max();
        consensus.nInstantSendConfirmationsRequired = 6;
        consensus.nInstantSendKeepLock = 24;
        consensus.nBudgetPaymentsStartBlock = std::numeric_limits<int>::max();
        consensus.nBudgetPaymentsCycleBlocks = 16616; // ~(60*24*30)/2.6, actual number of blocks per month is 200700 / 12 = 16725
        consensus.nBudgetPaymentsWindowBlocks = 100;
        consensus.nSuperblockStartBlock = std::numeric_limits<int>::max();
        consensus.nSuperblockStartHash = uint256();
        consensus.nSuperblockCycle = 16616; // ~(60*24*30)/2.6, actual number of blocks per month is 200700 / 12 = 16725
        consensus.nGovernanceMinQuorum = 10;
        consensus.nGovernanceFilterElements = 20000;
        consensus.nMasternodeMinimumConfirmations = 5;
        consensus.BIP34Height = std::numeric_limits<int>::max();
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.DIP0001Height = 0;
        consensus.DIP0003Height = 250;
        consensus.DIP0003EnforcementHeight = 750;
        consensus.DIP0003EnforcementHash = uint256();
        consensus.DIP0008Height = std::numeric_limits<int>::max();
        consensus.BRRHeight = std::numeric_limits<int>::max();
        consensus.MinBIP9WarningHeight = 5000;
        consensus.powLimit = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 16
        consensus.nPowTargetTimespan = 24 * 60 * 60; // Dash: 1 day
        consensus.nPowTargetSpacing = 2.5 * 60; // Dash: 2.5 minutes
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of DIP0001
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nThresholdStart = 25;

        // Deployment of BIP147
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nThresholdStart = 25;

        // Deployment of DIP0003
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].bit = 3;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nThresholdStart = 25;

        // Deployment of DIP0008
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].bit = 4;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nThresholdStart = 25;

        // Deployment of Block Reward Reallocation
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].bit = 5;
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].nStartTime = std::numeric_limits<int>::max();
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].nTimeout = std::numeric_limits<int>::max();
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].nWindowSize = 4032;
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].nThresholdStart = 3226; // 80% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].nThresholdMin = 2420; // 60% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].nFalloffCoeff = 5; // this corresponds to 10 periods

        // Deployment of DIP0020, DIP0021 and LLMQ_100_67 quorums
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].nStartTime = std::numeric_limits<int>::max();
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].nTimeout = std::numeric_limits<int>::max();
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].nWindowSize = 4032;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].nThresholdStart = 3226; // 80% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].nThresholdMin = 2420; // 60% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].nFalloffCoeff = 5; // this corresponds to 10 periods

        // Deployment of Quorum Rotation DIP and decreased proposal fee (Values to be determined)
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].bit = 7;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].nStartTime = 999999999999ULL; // TODO ENABLE BEFORE FINAL RELEASE
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].nTimeout = 999999999999ULL;   // TODO ENABLE BEFORE FINAL RELEASE
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].nWindowSize = 4032;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].nThresholdStart = 3226; // 80% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].nThresholdMin = 2420;   // 60% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].nFalloffCoeff = 5;      // this corresponds to 10 periods

        // datos consensus parameters
        consensus.nLastPoWBlock = 450;
        consensus.mnCollateral = 2500 * COIN;
        consensus.proofPublicKey = "dRHpwnnd7kwNhhH9W7vvCX4x5FPDyfeNK7";
        consensus.posLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 32
        consensus.nPosTargetTimespan = consensus.nPowTargetTimespan;
        consensus.nPosTargetSpacing = consensus.nPowTargetSpacing;
        consensus.nStakeMinValue = 150 * COIN;
        consensus.nStakeMaxValue = MAX_MONEY;
        consensus.nStakeMinAge = 10 * 60;
        consensus.nStakeMaxAge = 60 * 60 * 24 * 30;
        consensus.nStakeMaxHeight = std::numeric_limits<int>::max();
        consensus.nStakeMaxMultiplier = 3;
        consensus.nTokenHeight = std::numeric_limits<int>::max();

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256();

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256();

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x42;
        pchMessageStart[1] = 0xa7;
        pchMessageStart[2] = 0xca;
        pchMessageStart[3] = 0xe9;
        nDefaultPort = 8880;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 45;
        m_assumed_chain_state_size = 1;

        genesis = CreateGenesisBlock(1698810000, 61882, 0x1f00ffff, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00007fcceb238c788dee2a0fd753b904f3ab983ebc2b5f5f5a7e115ad276448e"));
        assert(genesis.hashMerkleRoot == uint256S("0xd1aa59f1847a4036dcdbd3c1c4015add886ab2bb16564bdaf873013cc792214f"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.

        // Datos addresses start with 'd'
        base58Prefixes[PUBKEY_ADDRESS] = {0x5a};
        // Datos script addresses start with 'e' or 'f'
        base58Prefixes[SCRIPT_ADDRESS] = {0x5e};
        // Datos private keys start with '7' or 'X'
        base58Prefixes[SECRET_KEY] = {0xcc};
        // Datos BIP32 pubkeys start with 'dtsp'
        base58Prefixes[EXT_PUBLIC_KEY] = {0x02, 0xff, 0x15, 0x66};
        // Datos BIP32 prvkeys start with 'dtsv'
        base58Prefixes[EXT_SECRET_KEY] = {0x02, 0xff, 0x15, 0x90};

        // Datos BIP44 coin type is '6144'
        nExtCoinType = 6144;

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        // long living quorum params
        AddLLMQ(Consensus::LLMQType::LLMQ_DATOS_64);
        AddLLMQ(Consensus::LLMQType::LLMQ_DATOS_1024);
        AddLLMQ(Consensus::LLMQType::LLMQ_400_85);
        AddLLMQ(Consensus::LLMQType::LLMQ_100_67);
        consensus.llmqTypeChainLocks = Consensus::LLMQType::LLMQ_DATOS_1024;
        consensus.llmqTypeInstantSend = Consensus::LLMQType::LLMQ_DATOS_64;
        consensus.llmqTypePlatform = Consensus::LLMQType::LLMQ_100_67;
        consensus.llmqTypeMnhf = Consensus::LLMQType::LLMQ_400_85;

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fRequireRoutableExternalIP = true;
        m_is_test_chain = false;
        fAllowMultipleAddressesFromGroup = false;
        fAllowMultiplePorts = false;
        nLLMQConnectionRetryTimeout = 60;

        nPoolMinParticipants = 3;
        nPoolMaxParticipants = 20;
        nFulfilledRequestExpireTime = 60*60; // fulfilled requests expire in 1 hour

        vSporkAddresses = {"dRrLXNGN9syvTHJxiABZWNJvXT2FLBre7n"};
        nMinSporkKeys = 1;
        fBIP9CheckMasternodesUpgraded = true;

        checkpointData = {
            {
                {0, genesis.GetHash()},
            }
        };

        chainTxData = ChainTxData{
            genesis.nTime,
            0,
            0
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = std::numeric_limits<int>::max();
        consensus.nMasternodePaymentsStartBlock = 0;
        consensus.nMasternodePaymentsIncreaseBlock = std::numeric_limits<int>::max();
        consensus.nMasternodePaymentsIncreasePeriod = std::numeric_limits<int>::max();
        consensus.nInstantSendConfirmationsRequired = 6;
        consensus.nInstantSendKeepLock = 24;
        consensus.nBudgetPaymentsStartBlock = 250;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nSuperblockStartBlock = 250;
        consensus.nSuperblockStartHash = uint256(); // do not check this on testnet
        consensus.nSuperblockCycle = 24; // Superblocks can be issued hourly on testnet
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 500;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.BIP34Height = std::numeric_limits<int>::max();
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.DIP0001Height = 0;
        consensus.DIP0003Height = 250;
        consensus.DIP0003EnforcementHeight = 750;
        consensus.DIP0003EnforcementHash = uint256();
        consensus.DIP0008Height = std::numeric_limits<int>::max();
        consensus.BRRHeight = std::numeric_limits<int>::max();
        consensus.MinBIP9WarningHeight = 5000;
        consensus.powLimit = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 16
        consensus.nPowTargetTimespan = 24 * 60 * 60; // Dash: 1 day
        consensus.nPowTargetSpacing = 2.5 * 60; // Dash: 2.5 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 256; // 75% for testchains
        consensus.nMinerConfirmationWindow = 384; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of DIP0001
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nThresholdStart = 25;

        // Deployment of BIP147
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nThresholdStart = 25;

        // Deployment of DIP0003
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].bit = 3;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nThresholdStart = 25;

        // Deployment of DIP0008
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].bit = 4;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nThresholdStart = 25;

        // Deployment of Block Reward Reallocation
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].bit = 5;
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].nStartTime = std::numeric_limits<int>::max();
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].nTimeout = std::numeric_limits<int>::max();
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].nWindowSize = 4032;
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].nThresholdStart = 3226; // 80% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].nThresholdMin = 2420; // 60% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].nFalloffCoeff = 5; // this corresponds to 10 periods

        // Deployment of DIP0020, DIP0021 and LLMQ_100_67 quorums
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].nStartTime = std::numeric_limits<int>::max();
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].nTimeout = std::numeric_limits<int>::max();
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].nWindowSize = 4032;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].nThresholdStart = 3226; // 80% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].nThresholdMin = 2420; // 60% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].nFalloffCoeff = 5; // this corresponds to 10 periods

        // Deployment of Quorum Rotation DIP and decreased proposal fee (Values to be determined)
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].bit = 7;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].nStartTime = 999999999999ULL; // TODO ENABLE BEFORE FINAL RELEASE
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].nTimeout = 999999999999ULL;   // TODO ENABLE BEFORE FINAL RELEASE
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].nWindowSize = 4032;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].nThresholdStart = 3226; // 80% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].nThresholdMin = 2420;   // 60% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].nFalloffCoeff = 5;      // this corresponds to 10 periods

        // datos consensus parameters
        consensus.nLastPoWBlock = 250;
        consensus.mnCollateral = 500000 * COIN;
        consensus.proofPublicKey = "dRHpwnnd7kwNhhH9W7vvCX4x5FPDyfeNK7";
        consensus.posLimit = uint256S("000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 28
        consensus.nPosTargetTimespan = consensus.nPowTargetTimespan;
        consensus.nPosTargetSpacing = consensus.nPowTargetSpacing;
        consensus.nStakeMinValue = 0 * COIN;
        consensus.nStakeMaxValue = MAX_MONEY;
        consensus.nStakeMinAge = 10 * 60;
        consensus.nStakeMaxAge = 60 * 60 * 24 * 90;
        consensus.nStakeMaxHeight = 1;
        consensus.nStakeMaxMultiplier = 3;
        consensus.nTokenHeight = std::numeric_limits<int>::max();

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256();

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256();

        pchMessageStart[0] = 0xc1;
        pchMessageStart[1] = 0x47;
        pchMessageStart[2] = 0x93;
        pchMessageStart[3] = 0xb0;
        nDefaultPort = 8890;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 4;
        m_assumed_chain_state_size = 1;

        genesis = CreateGenesisBlock(1734225997, 39574, 0x1f00ffff, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000a98d34ad94bce26d897d248d385837d358c032daa5a15f5f93723950e2c"));
        assert(genesis.hashMerkleRoot == uint256S("0xd1aa59f1847a4036dcdbd3c1c4015add886ab2bb16564bdaf873013cc792214f"));

        vFixedSeeds.clear();
        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));
        vSeeds.clear();

        // Datos addresses start with 'd'
        base58Prefixes[PUBKEY_ADDRESS] = {0x5a};
        // Datos script addresses start with 'e' or 'f'
        base58Prefixes[SCRIPT_ADDRESS] = {0x5e};
        // Datos private keys start with '7' or 'X'
        base58Prefixes[SECRET_KEY] = {0xcc};
        // Datos BIP32 pubkeys start with 'dtsp'
        base58Prefixes[EXT_PUBLIC_KEY] = {0x02, 0xff, 0x15, 0x66};
        // Datos BIP32 prvkeys start with 'dtsv'
        base58Prefixes[EXT_SECRET_KEY] = {0x02, 0xff, 0x15, 0x90};

        // Datos BIP44 coin type is '6144'
        nExtCoinType = 6144;

        // long living quorum params
        AddLLMQ(Consensus::LLMQType::LLMQ_TEST);
        AddLLMQ(Consensus::LLMQType::LLMQ_DATOS_64);
        AddLLMQ(Consensus::LLMQType::LLMQ_DATOS_1024);
        AddLLMQ(Consensus::LLMQType::LLMQ_400_85);
        AddLLMQ(Consensus::LLMQType::LLMQ_100_67);
        consensus.llmqTypeChainLocks = Consensus::LLMQType::LLMQ_TEST;
        consensus.llmqTypeInstantSend = Consensus::LLMQType::LLMQ_TEST;
        consensus.llmqTypePlatform = Consensus::LLMQType::LLMQ_100_67;
        consensus.llmqTypeMnhf = Consensus::LLMQType::LLMQ_TEST;

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fRequireRoutableExternalIP = true;
        m_is_test_chain = true;
        fAllowMultipleAddressesFromGroup = false;
        fAllowMultiplePorts = true;
        nLLMQConnectionRetryTimeout = 60;

        nPoolMinParticipants = 2;
        nPoolMaxParticipants = 20;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes

        vSporkAddresses = {"dRrLXNGN9syvTHJxiABZWNJvXT2FLBre7n"};
        nMinSporkKeys = 1;
        fBIP9CheckMasternodesUpgraded = true;

        checkpointData = {
            {
                {0, genesis.GetHash()},
            }
        };

        chainTxData = ChainTxData{
            genesis.nTime,
            0,
            0
        };
    }
};

/**
 * Devnet
 */
class CDevNetParams : public CChainParams {
public:
    explicit CDevNetParams(const ArgsManager& args) {
        strNetworkID = "devnet";
        consensus.nSubsidyHalvingInterval = std::numeric_limits<int>::max();
        consensus.nMasternodePaymentsStartBlock = 0;
        consensus.nMasternodePaymentsIncreaseBlock = std::numeric_limits<int>::max();
        consensus.nMasternodePaymentsIncreasePeriod = std::numeric_limits<int>::max();
        consensus.nInstantSendConfirmationsRequired = 6;
        consensus.nInstantSendKeepLock = 24;
        consensus.nBudgetPaymentsStartBlock = 4100;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nSuperblockStartBlock = 4200; // NOTE: Should satisfy nSuperblockStartBlock > nBudgetPeymentsStartBlock
        consensus.nSuperblockStartHash = uint256(); // do not check this on testnet
        consensus.nSuperblockCycle = 24; // Superblocks can be issued hourly on testnet
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 500;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.BIP34Height = std::numeric_limits<int>::max();
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.DIP0001Height = 0;
        consensus.DIP0003Height = 1000;
        consensus.DIP0003EnforcementHeight = std::numeric_limits<int>::max();
        consensus.DIP0003EnforcementHash = uint256();
        consensus.DIP0008Height = std::numeric_limits<int>::max();
        consensus.BRRHeight = std::numeric_limits<int>::max();
        consensus.MinBIP9WarningHeight = 5000;
        consensus.powLimit = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 16
        consensus.nPowTargetTimespan = 24 * 60 * 60; // Dash: 1 day
        consensus.nPowTargetSpacing = 2.5 * 60; // Dash: 2.5 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of DIP0001
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nThresholdStart = 25;

        // Deployment of BIP147
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nThresholdStart = 25;

        // Deployment of DIP0003
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].bit = 3;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nThresholdStart = 25;

        // Deployment of DIP0008
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].bit = 4;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nThresholdStart = 25;

        // Deployment of Block Reward Reallocation
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].bit = 5;
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].nStartTime = std::numeric_limits<int>::max();
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].nTimeout = std::numeric_limits<int>::max();
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].nWindowSize = 4032;
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].nThresholdStart = 3226; // 80% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].nThresholdMin = 2420; // 60% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].nFalloffCoeff = 5; // this corresponds to 10 periods

        // Deployment of DIP0020, DIP0021 and LLMQ_100_67 quorums
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].nStartTime = 1625097600; // July 1st, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].nTimeout = 1656633600; // July 1st, 2022
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].nWindowSize = 4032;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].nThresholdStart = 3226; // 80% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].nThresholdMin = 2420; // 60% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].nFalloffCoeff = 5; // this corresponds to 10 periods

        // Deployment of Quorum Rotation DIP and decreased proposal fee (Values to be determined)
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].bit = 7;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].nStartTime = 999999999999ULL; // TODO ENABLE BEFORE FINAL RELEASE
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].nTimeout = 999999999999ULL;   // TODO ENABLE BEFORE FINAL RELEASE
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].nWindowSize = 4032;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].nThresholdStart = 3226; // 80% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].nThresholdMin = 2420;   // 60% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].nFalloffCoeff = 5;      // this corresponds to 10 periods

        // datos consensus parameters
        consensus.nLastPoWBlock = 1000;
        consensus.mnCollateral = 500000 * COIN;
        consensus.posLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 32
        consensus.nPosTargetTimespan = consensus.nPowTargetTimespan;
        consensus.nPosTargetSpacing = consensus.nPowTargetSpacing;
        consensus.nStakeMinValue = 0 * COIN;
        consensus.nStakeMaxValue = MAX_MONEY;
        consensus.nStakeMinAge = 10 * 60;
        consensus.nStakeMaxAge = 60 * 60 * 24 * 30;
        consensus.nStakeMaxHeight = 1;        // not enabled
        consensus.nStakeMaxMultiplier = 1;    // 1x multiplier
        consensus.nTokenHeight = std::numeric_limits<int>::max();

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256();

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256();

        pchMessageStart[0] = 0xd5;
        pchMessageStart[1] = 0x88;
        pchMessageStart[2] = 0xba;
        pchMessageStart[3] = 0x7b;
        nDefaultPort = 8900;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateDevnetSubsidyAndDiffParametersFromArgs(args);
        genesis = CreateGenesisBlock(1697248000, 2, 0x1f00ffff, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x29714ed4d24d182dc4c9ea6cce414d87a4991d91cfe96cb18f629981d1a75c39"));
        assert(genesis.hashMerkleRoot == uint256S("0xd1aa59f1847a4036dcdbd3c1c4015add886ab2bb16564bdaf873013cc792214f"));

        devnetGenesis = FindDevNetGenesisBlock(genesis, 50 * COIN);
        consensus.hashDevnetGenesisBlock = devnetGenesis.GetHash();

        vFixedSeeds.clear();
        vSeeds.clear();
        //vSeeds.push_back(CDNSSeedData("dashevo.org",  "devnet-seed.dashevo.org"));

        // Testnet Dash addresses start with 'y'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,140);
        // Testnet Dash script addresses start with '8' or '9'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,19);
        // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        // Testnet Dash BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        // Testnet Dash BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        // Testnet Dash BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 1;

        // long living quorum params
        AddLLMQ(Consensus::LLMQType::LLMQ_DATOS_64);
        AddLLMQ(Consensus::LLMQType::LLMQ_60_75);
        AddLLMQ(Consensus::LLMQType::LLMQ_DATOS_1024);
        AddLLMQ(Consensus::LLMQType::LLMQ_400_85);
        AddLLMQ(Consensus::LLMQType::LLMQ_100_67);
        AddLLMQ(Consensus::LLMQType::LLMQ_DEVNET);
        AddLLMQ(Consensus::LLMQType::LLMQ_DEVNET_DIP0024);
        consensus.llmqTypeChainLocks = Consensus::LLMQType::LLMQ_DATOS_64;
        consensus.llmqTypeInstantSend = Consensus::LLMQType::LLMQ_DATOS_64;
        consensus.llmqTypeDIP0024InstantSend = Consensus::LLMQType::LLMQ_60_75;
        consensus.llmqTypePlatform = Consensus::LLMQType::LLMQ_100_67;
        consensus.llmqTypeMnhf = Consensus::LLMQType::LLMQ_DATOS_64;

        UpdateDevnetLLMQChainLocksFromArgs(args);
        UpdateDevnetLLMQInstantSendFromArgs(args);
        UpdateDevnetLLMQInstantSendDIP0024FromArgs(args);
        UpdateLLMQDevnetParametersFromArgs(args);
        UpdateDevnetPowTargetSpacingFromArgs(args);

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fRequireRoutableExternalIP = true;
        m_is_test_chain = true;
        fAllowMultipleAddressesFromGroup = true;
        fAllowMultiplePorts = true;
        nLLMQConnectionRetryTimeout = 60;

        nPoolMinParticipants = 2;
        nPoolMaxParticipants = 20;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes

        vSporkAddresses = {"yjPtiKh2uwk3bDutTEA2q9mCtXyiZRWn55"};
        nMinSporkKeys = 1;
        // devnets are started with no blocks and no MN, so we can't check for upgraded MN (as there are none)
        fBIP9CheckMasternodesUpgraded = false;

        checkpointData = (CCheckpointData) {
            {
                {0, genesis.GetHash()},
            }
        };

        chainTxData = ChainTxData{
            devnetGenesis.GetBlockTime(), // * UNIX timestamp of devnet genesis block
            2,                            // * we only have 2 coinbase transactions when a devnet is started up
            0.01                          // * estimated number of transactions per second
        };
    }

    /**
     * Allows modifying the subsidy and difficulty devnet parameters.
     */
    void UpdateDevnetSubsidyAndDiffParameters(int nMinimumDifficultyBlocks, int nHighSubsidyBlocks, int nHighSubsidyFactor)
    {
        consensus.nMinimumDifficultyBlocks = nMinimumDifficultyBlocks;
        consensus.nHighSubsidyBlocks = nHighSubsidyBlocks;
        consensus.nHighSubsidyFactor = nHighSubsidyFactor;
    }
    void UpdateDevnetSubsidyAndDiffParametersFromArgs(const ArgsManager& args);

    /**
     * Allows modifying the LLMQ type for ChainLocks.
     */
    void UpdateDevnetLLMQChainLocks(Consensus::LLMQType llmqType)
    {
        consensus.llmqTypeChainLocks = llmqType;
    }
    void UpdateDevnetLLMQChainLocksFromArgs(const ArgsManager& args);

    /**
     * Allows modifying the LLMQ type for InstantSend.
     */
    void UpdateDevnetLLMQInstantSend(Consensus::LLMQType llmqType)
    {
        consensus.llmqTypeInstantSend = llmqType;
    }

    /**
     * Allows modifying the LLMQ type for InstantSend (DIP0024).
     */
    void UpdateDevnetLLMQDIP0024InstantSend(Consensus::LLMQType llmqType)
    {
        consensus.llmqTypeDIP0024InstantSend = llmqType;
    }

    /**
     * Allows modifying PowTargetSpacing
     */
    void UpdateDevnetPowTargetSpacing(int64_t nPowTargetSpacing)
    {
        consensus.nPowTargetSpacing = nPowTargetSpacing;
    }

    /**
     * Allows modifying parameters of the devnet LLMQ
     */
    void UpdateLLMQDevnetParameters(int size, int threshold)
    {
        auto params = ranges::find_if(consensus.llmqs, [](const auto& llmq){ return llmq.type == Consensus::LLMQType::LLMQ_DEVNET;});
        assert(params != consensus.llmqs.end());
        params->size = size;
        params->minSize = threshold;
        params->threshold = threshold;
        params->dkgBadVotesThreshold = threshold;
    }
    void UpdateLLMQDevnetParametersFromArgs(const ArgsManager& args);
    void UpdateDevnetLLMQInstantSendFromArgs(const ArgsManager& args);
    void UpdateDevnetLLMQInstantSendDIP0024FromArgs(const ArgsManager& args);
    void UpdateDevnetPowTargetSpacingFromArgs(const ArgsManager& args);
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMasternodePaymentsStartBlock = 240;
        consensus.nMasternodePaymentsIncreaseBlock = 350;
        consensus.nMasternodePaymentsIncreasePeriod = 10;
        consensus.nInstantSendConfirmationsRequired = 2;
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 1000;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nSuperblockStartBlock = 1500;
        consensus.nSuperblockStartHash = uint256(); // do not check this on regtest
        consensus.nSuperblockCycle = 10;
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 100;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.BIP34Height = 500; // BIP34 activated on regtest (Used in functional tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in functional tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in functional tests)
        consensus.DIP0001Height = 2000;
        consensus.DIP0003Height = 432;
        consensus.DIP0003EnforcementHeight = 500;
        consensus.DIP0003EnforcementHash = uint256();
        consensus.DIP0008Height = 432;
        consensus.BRRHeight = 2500; // see block_reward_reallocation_tests
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 16
        consensus.nPowTargetTimespan = 24 * 60 * 60; // Dash: 1 day
        consensus.nPowTargetSpacing = 2.5 * 60; // Dash: 2.5 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of DIP0001
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nThresholdStart = 25;

        // Deployment of BIP147
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nThresholdStart = 25;

        // Deployment of DIP0003
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].bit = 3;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nThresholdStart = 25;

        // Deployment of DIP0008
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].bit = 4;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nThresholdStart = 25;

        // Deployment of Block Reward Reallocation
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].bit = 5;
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].nStartTime = std::numeric_limits<int>::max();
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].nTimeout = std::numeric_limits<int>::max();
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].nWindowSize = 4032;
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].nThresholdStart = 3226; // 80% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].nThresholdMin = 2420; // 60% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_REALLOC].nFalloffCoeff = 5; // this corresponds to 10 periods

        // Deployment of DIP0020, DIP0021 and LLMQ_100_67 quorums
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].nStartTime = 1625097600; // July 1st, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].nTimeout = 1656633600; // July 1st, 2022
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].nWindowSize = 4032;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].nThresholdStart = 3226; // 80% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].nThresholdMin = 2420; // 60% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0020].nFalloffCoeff = 5; // this corresponds to 10 periods

        // Deployment of Quorum Rotation DIP and decreased proposal fee (Values to be determined)
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].bit = 7;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].nStartTime = 999999999999ULL; // TODO ENABLE BEFORE FINAL RELEASE
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].nTimeout = 999999999999ULL;   // TODO ENABLE BEFORE FINAL RELEASE
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].nWindowSize = 4032;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].nThresholdStart = 3226; // 80% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].nThresholdMin = 2420;   // 60% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0024].nFalloffCoeff = 5;      // this corresponds to 10 periods


        // datos consensus parameters
        consensus.nLastPoWBlock = 1000;
        consensus.mnCollateral = 500000 * COIN;
        consensus.posLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 32
        consensus.nPosTargetTimespan = consensus.nPowTargetTimespan;
        consensus.nPosTargetSpacing = consensus.nPowTargetSpacing;
        consensus.nStakeMinValue = 0 * COIN;
        consensus.nStakeMaxValue = MAX_MONEY;
        consensus.nStakeMinAge = 10 * 60;
        consensus.nStakeMaxAge = 60 * 60 * 24 * 30;
        consensus.nStakeMaxHeight = 1;        // not enabled
        consensus.nStakeMaxMultiplier = 1;    // 1x multiplier
        consensus.nTokenHeight = 100;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256();

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256();

        pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0xb4;
        pchMessageStart[2] = 0x78;
        pchMessageStart[3] = 0xe0;
        nDefaultPort = 8910;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateVersionBitsParametersFromArgs(args);
        UpdateDIP3ParametersFromArgs(args);
        UpdateDIP8ParametersFromArgs(args);
        UpdateBudgetParametersFromArgs(args);

        genesis = CreateGenesisBlock(1697249000, 27180, 0x1f00ffff, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0000d94cc68e7e6af6d6dd1b7898090373c87b357408971427a9420318a7f9e6"));
        assert(genesis.hashMerkleRoot == uint256S("0xd1aa59f1847a4036dcdbd3c1c4015add886ab2bb16564bdaf873013cc792214f"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = true;
        fRequireRoutableExternalIP = false;
        m_is_test_chain = true;
        fAllowMultipleAddressesFromGroup = true;
        fAllowMultiplePorts = true;
        nLLMQConnectionRetryTimeout = 1; // must be lower then the LLMQ signing session timeout so that tests have control over failing behavior

        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes
        nPoolMinParticipants = 2;
        nPoolMaxParticipants = 20;

        // privKey: cP4EKFyJsHT39LDqgdcB43Y3YXjNyjb5Fuas1GQSeAtjnZWmZEQK
        vSporkAddresses = {"yj949n1UH6fDhw6HtVE5VMj2iSTaSWBMcW"};
        nMinSporkKeys = 1;
        // regtest usually has no masternodes in most tests, so don't check for upgraged MNs
        fBIP9CheckMasternodesUpgraded = false;

        checkpointData = {
            {
                {0, genesis.GetHash()},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        // Regtest Dash addresses start with 'y'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,140);
        // Regtest Dash script addresses start with '8' or '9'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,19);
        // Regtest private keys start with '9' or 'c' (Bitcoin defaults)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        // Regtest Dash BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        // Regtest Dash BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        // Regtest Dash BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 1;

        // long living quorum params
        AddLLMQ(Consensus::LLMQType::LLMQ_TEST);
        AddLLMQ(Consensus::LLMQType::LLMQ_TEST_INSTANTSEND);
        AddLLMQ(Consensus::LLMQType::LLMQ_TEST_V17);
        AddLLMQ(Consensus::LLMQType::LLMQ_TEST_DIP0024);
        consensus.llmqTypeChainLocks = Consensus::LLMQType::LLMQ_TEST;
        consensus.llmqTypeInstantSend = Consensus::LLMQType::LLMQ_TEST_INSTANTSEND;
        consensus.llmqTypeDIP0024InstantSend = Consensus::LLMQType::LLMQ_TEST_DIP0024;
        consensus.llmqTypePlatform = Consensus::LLMQType::LLMQ_TEST;
        consensus.llmqTypeMnhf = Consensus::LLMQType::LLMQ_TEST;

        UpdateLLMQTestParametersFromArgs(args, Consensus::LLMQType::LLMQ_TEST);
        UpdateLLMQTestParametersFromArgs(args, Consensus::LLMQType::LLMQ_TEST_INSTANTSEND);
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout, int64_t nWindowSize, int64_t nThresholdStart, int64_t nThresholdMin, int64_t nFalloffCoeff)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
        if (nWindowSize != -1) {
            consensus.vDeployments[d].nWindowSize = nWindowSize;
        }
        if (nThresholdStart != -1) {
            consensus.vDeployments[d].nThresholdStart = nThresholdStart;
        }
        if (nThresholdMin != -1) {
            consensus.vDeployments[d].nThresholdMin = nThresholdMin;
        }
        if (nFalloffCoeff != -1) {
            consensus.vDeployments[d].nFalloffCoeff = nFalloffCoeff;
        }
    }
    void UpdateVersionBitsParametersFromArgs(const ArgsManager& args);

    /**
     * Allows modifying the DIP3 activation and enforcement height
     */
    void UpdateDIP3Parameters(int nActivationHeight, int nEnforcementHeight)
    {
        consensus.DIP0003Height = nActivationHeight;
        consensus.DIP0003EnforcementHeight = nEnforcementHeight;
    }
    void UpdateDIP3ParametersFromArgs(const ArgsManager& args);

    /**
     * Allows modifying the DIP8 activation height
     */
    void UpdateDIP8Parameters(int nActivationHeight)
    {
        consensus.DIP0008Height = nActivationHeight;
    }
    void UpdateDIP8ParametersFromArgs(const ArgsManager& args);

    /**
     * Allows modifying the budget regtest parameters.
     */
    void UpdateBudgetParameters(int nMasternodePaymentsStartBlock, int nBudgetPaymentsStartBlock, int nSuperblockStartBlock)
    {
        consensus.nMasternodePaymentsStartBlock = nMasternodePaymentsStartBlock;
        consensus.nBudgetPaymentsStartBlock = nBudgetPaymentsStartBlock;
        consensus.nSuperblockStartBlock = nSuperblockStartBlock;
    }
    void UpdateBudgetParametersFromArgs(const ArgsManager& args);

    /**
     * Allows modifying parameters of the test LLMQ
     */
    void UpdateLLMQTestParameters(int size, int threshold, const Consensus::LLMQType llmqType)
    {
        auto params = ranges::find_if(consensus.llmqs, [llmqType](const auto& llmq){ return llmq.type == llmqType;});
        assert(params != consensus.llmqs.end());
        params->size = size;
        params->minSize = threshold;
        params->threshold = threshold;
        params->dkgBadVotesThreshold = threshold;
    }
    void UpdateLLMQTestParametersFromArgs(const ArgsManager& args, const Consensus::LLMQType llmqType);
};

void CRegTestParams::UpdateVersionBitsParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams;
        boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
        if (vDeploymentParams.size() != 3 && vDeploymentParams.size() != 5 && vDeploymentParams.size() != 7) {
            throw std::runtime_error("Version bits parameters malformed, expecting "
                    "<deployment>:<start>:<end> or "
                    "<deployment>:<start>:<end>:<window>:<threshold> or "
                    "<deployment>:<start>:<end>:<window>:<thresholdstart>:<thresholdmin>:<falloffcoeff>");
        }
        int64_t nStartTime, nTimeout, nWindowSize = -1, nThresholdStart = -1, nThresholdMin = -1, nFalloffCoeff = -1;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        if (vDeploymentParams.size() >= 5) {
            if (!ParseInt64(vDeploymentParams[3], &nWindowSize)) {
                throw std::runtime_error(strprintf("Invalid nWindowSize (%s)", vDeploymentParams[3]));
            }
            if (!ParseInt64(vDeploymentParams[4], &nThresholdStart)) {
                throw std::runtime_error(strprintf("Invalid nThresholdStart (%s)", vDeploymentParams[4]));
            }
        }
        if (vDeploymentParams.size() == 7) {
            if (!ParseInt64(vDeploymentParams[5], &nThresholdMin)) {
                throw std::runtime_error(strprintf("Invalid nThresholdMin (%s)", vDeploymentParams[5]));
            }
            if (!ParseInt64(vDeploymentParams[6], &nFalloffCoeff)) {
                throw std::runtime_error(strprintf("Invalid nFalloffCoeff (%s)", vDeploymentParams[6]));
            }
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout, nWindowSize, nThresholdStart, nThresholdMin, nFalloffCoeff);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld, window=%ld, thresholdstart=%ld, thresholdmin=%ld, falloffcoeff=%ld\n",
                          vDeploymentParams[0], nStartTime, nTimeout, nWindowSize, nThresholdStart, nThresholdMin, nFalloffCoeff);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

void CRegTestParams::UpdateDIP3ParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-dip3params")) return;

    std::string strParams = args.GetArg("-dip3params", "");
    std::vector<std::string> vParams;
    boost::split(vParams, strParams, boost::is_any_of(":"));
    if (vParams.size() != 2) {
        throw std::runtime_error("DIP3 parameters malformed, expecting <activation>:<enforcement>");
    }
    int nDIP3ActivationHeight, nDIP3EnforcementHeight;
    if (!ParseInt32(vParams[0], &nDIP3ActivationHeight)) {
        throw std::runtime_error(strprintf("Invalid activation height (%s)", vParams[0]));
    }
    if (!ParseInt32(vParams[1], &nDIP3EnforcementHeight)) {
        throw std::runtime_error(strprintf("Invalid enforcement height (%s)", vParams[1]));
    }
    LogPrintf("Setting DIP3 parameters to activation=%ld, enforcement=%ld\n", nDIP3ActivationHeight, nDIP3EnforcementHeight);
    UpdateDIP3Parameters(nDIP3ActivationHeight, nDIP3EnforcementHeight);
}

void CRegTestParams::UpdateDIP8ParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-dip8params")) return;

    std::string strParams = args.GetArg("-dip8params", "");
    std::vector<std::string> vParams;
    boost::split(vParams, strParams, boost::is_any_of(":"));
    if (vParams.size() != 1) {
        throw std::runtime_error("DIP8 parameters malformed, expecting <activation>");
    }
    int nDIP8ActivationHeight;
    if (!ParseInt32(vParams[0], &nDIP8ActivationHeight)) {
        throw std::runtime_error(strprintf("Invalid activation height (%s)", vParams[0]));
    }
    LogPrintf("Setting DIP8 parameters to activation=%ld\n", nDIP8ActivationHeight);
    UpdateDIP8Parameters(nDIP8ActivationHeight);
}

void CRegTestParams::UpdateBudgetParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-budgetparams")) return;

    std::string strParams = args.GetArg("-budgetparams", "");
    std::vector<std::string> vParams;
    boost::split(vParams, strParams, boost::is_any_of(":"));
    if (vParams.size() != 3) {
        throw std::runtime_error("Budget parameters malformed, expecting <masternode>:<budget>:<superblock>");
    }
    int nMasternodePaymentsStartBlock, nBudgetPaymentsStartBlock, nSuperblockStartBlock;
    if (!ParseInt32(vParams[0], &nMasternodePaymentsStartBlock)) {
        throw std::runtime_error(strprintf("Invalid masternode start height (%s)", vParams[0]));
    }
    if (!ParseInt32(vParams[1], &nBudgetPaymentsStartBlock)) {
        throw std::runtime_error(strprintf("Invalid budget start block (%s)", vParams[1]));
    }
    if (!ParseInt32(vParams[2], &nSuperblockStartBlock)) {
        throw std::runtime_error(strprintf("Invalid superblock start height (%s)", vParams[2]));
    }
    LogPrintf("Setting budget parameters to masternode=%ld, budget=%ld, superblock=%ld\n", nMasternodePaymentsStartBlock, nBudgetPaymentsStartBlock, nSuperblockStartBlock);
    UpdateBudgetParameters(nMasternodePaymentsStartBlock, nBudgetPaymentsStartBlock, nSuperblockStartBlock);
}

void CRegTestParams::UpdateLLMQTestParametersFromArgs(const ArgsManager& args, const Consensus::LLMQType llmqType)
{
    assert(llmqType == Consensus::LLMQType::LLMQ_TEST || llmqType == Consensus::LLMQType::LLMQ_TEST_INSTANTSEND);

    std::string cmd_param{"-llmqtestparams"}, llmq_name{"LLMQ_TEST"};
    if (llmqType == Consensus::LLMQType::LLMQ_TEST_INSTANTSEND) {
        cmd_param = "-llmqtestinstantsendparams";
        llmq_name = "LLMQ_TEST_INSTANTSEND";
    }

    if (!args.IsArgSet(cmd_param)) return;

    std::string strParams = args.GetArg(cmd_param, "");
    std::vector<std::string> vParams;
    boost::split(vParams, strParams, boost::is_any_of(":"));
    if (vParams.size() != 2) {
        throw std::runtime_error(strprintf("%s parameters malformed, expecting <size>:<threshold>", llmq_name));
    }
    int size, threshold;
    if (!ParseInt32(vParams[0], &size)) {
        throw std::runtime_error(strprintf("Invalid %s size (%s)", llmq_name, vParams[0]));
    }
    if (!ParseInt32(vParams[1], &threshold)) {
        throw std::runtime_error(strprintf("Invalid %s threshold (%s)", llmq_name, vParams[1]));
    }
    LogPrintf("Setting %s parameters to size=%ld, threshold=%ld\n", llmq_name, size, threshold);
    UpdateLLMQTestParameters(size, threshold, llmqType);
}

void CDevNetParams::UpdateDevnetSubsidyAndDiffParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-minimumdifficultyblocks") && !args.IsArgSet("-highsubsidyblocks") && !args.IsArgSet("-highsubsidyfactor")) return;

    int nMinimumDifficultyBlocks = gArgs.GetArg("-minimumdifficultyblocks", consensus.nMinimumDifficultyBlocks);
    int nHighSubsidyBlocks = gArgs.GetArg("-highsubsidyblocks", consensus.nHighSubsidyBlocks);
    int nHighSubsidyFactor = gArgs.GetArg("-highsubsidyfactor", consensus.nHighSubsidyFactor);
    LogPrintf("Setting minimumdifficultyblocks=%ld, highsubsidyblocks=%ld, highsubsidyfactor=%ld\n", nMinimumDifficultyBlocks, nHighSubsidyBlocks, nHighSubsidyFactor);
    UpdateDevnetSubsidyAndDiffParameters(nMinimumDifficultyBlocks, nHighSubsidyBlocks, nHighSubsidyFactor);
}

void CDevNetParams::UpdateDevnetLLMQChainLocksFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-llmqchainlocks")) return;

    std::string strLLMQType = gArgs.GetArg("-llmqchainlocks", std::string(GetLLMQ(consensus.llmqTypeChainLocks).name));

    Consensus::LLMQType llmqType = Consensus::LLMQType::LLMQ_NONE;
    for (const auto& params : consensus.llmqs) {
        if (params.name == strLLMQType) {
            if (params.useRotation) {
                throw std::runtime_error("LLMQ type specified for -llmqchainlocks must NOT use rotation");
            }
            llmqType = params.type;
        }
    }
    if (llmqType == Consensus::LLMQType::LLMQ_NONE) {
        throw std::runtime_error("Invalid LLMQ type specified for -llmqchainlocks.");
    }
    LogPrintf("Setting llmqchainlocks to size=%ld\n", static_cast<uint8_t>(llmqType));
    UpdateDevnetLLMQChainLocks(llmqType);
}

void CDevNetParams::UpdateDevnetLLMQInstantSendFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-llmqinstantsend")) return;

    std::string strLLMQType = gArgs.GetArg("-llmqinstantsend", std::string(GetLLMQ(consensus.llmqTypeInstantSend).name));

    Consensus::LLMQType llmqType = Consensus::LLMQType::LLMQ_NONE;
    for (const auto& params : consensus.llmqs) {
        if (params.name == strLLMQType) {
            if (params.useRotation) {
                throw std::runtime_error("LLMQ type specified for -llmqinstantsend must NOT use rotation");
            }
            llmqType = params.type;
        }
    }
    if (llmqType == Consensus::LLMQType::LLMQ_NONE) {
        throw std::runtime_error("Invalid LLMQ type specified for -llmqinstantsend.");
    }
    LogPrintf("Setting llmqinstantsend to size=%ld\n", static_cast<uint8_t>(llmqType));
    UpdateDevnetLLMQInstantSend(llmqType);
}

void CDevNetParams::UpdateDevnetLLMQInstantSendDIP0024FromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-llmqinstantsenddip0024")) return;

    std::string strLLMQType = gArgs.GetArg("-llmqinstantsenddip0024", std::string(GetLLMQ(consensus.llmqTypeDIP0024InstantSend).name));

    Consensus::LLMQType llmqType = Consensus::LLMQType::LLMQ_NONE;
    for (const auto& params : consensus.llmqs) {
        if (params.name == strLLMQType) {
            if (!params.useRotation) {
                throw std::runtime_error("LLMQ type specified for -llmqinstantsenddip0024 must use rotation");
            }
            llmqType = params.type;
        }
    }
    if (llmqType == Consensus::LLMQType::LLMQ_NONE) {
        throw std::runtime_error("Invalid LLMQ type specified for -llmqinstantsenddip0024.");
    }
    LogPrintf("Setting llmqinstantsenddip0024 to size=%ld\n", static_cast<uint8_t>(llmqType));
    UpdateDevnetLLMQDIP0024InstantSend(llmqType);
}

void CDevNetParams::UpdateDevnetPowTargetSpacingFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-powtargetspacing")) return;

    std::string strPowTargetSpacing = gArgs.GetArg("-powtargetspacing", "");

    int64_t powTargetSpacing;
    if (!ParseInt64(strPowTargetSpacing, &powTargetSpacing)) {
        throw std::runtime_error(strprintf("Invalid parsing of powTargetSpacing (%s)", strPowTargetSpacing));
    }

    if (powTargetSpacing < 1) {
        throw std::runtime_error(strprintf("Invalid value of powTargetSpacing (%s)", strPowTargetSpacing));
    }

    LogPrintf("Setting powTargetSpacing to %ld\n", powTargetSpacing);
    UpdateDevnetPowTargetSpacing(powTargetSpacing);
}

void CDevNetParams::UpdateLLMQDevnetParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-llmqdevnetparams")) return;

    std::string strParams = args.GetArg("-llmqdevnetparams", "");
    std::vector<std::string> vParams;
    boost::split(vParams, strParams, boost::is_any_of(":"));
    if (vParams.size() != 2) {
        throw std::runtime_error("LLMQ_DEVNET parameters malformed, expecting <size>:<threshold>");
    }
    int size, threshold;
    if (!ParseInt32(vParams[0], &size)) {
        throw std::runtime_error(strprintf("Invalid LLMQ_DEVNET size (%s)", vParams[0]));
    }
    if (!ParseInt32(vParams[1], &threshold)) {
        throw std::runtime_error(strprintf("Invalid LLMQ_DEVNET threshold (%s)", vParams[1]));
    }
    LogPrintf("Setting LLMQ_DEVNET parameters to size=%ld, threshold=%ld\n", size, threshold);
    UpdateLLMQDevnetParameters(size, threshold);
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::make_unique<CMainParams>();
    else if (chain == CBaseChainParams::TESTNET)
        return std::make_unique<CTestNetParams>();
    else if (chain == CBaseChainParams::DEVNET)
        return std::make_unique<CDevNetParams>(gArgs);
    else if (chain == CBaseChainParams::REGTEST)
        return std::make_unique<CRegTestParams>(gArgs);

    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}
