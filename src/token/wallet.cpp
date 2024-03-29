// Copyright (c) 2023 datos
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/policy.h>
#include <rpc/protocol.h>
#include <token/util.h>
#include <token/verify.h>
#include <txmempool.h>
#include <validation.h>
#include <wallet/wallet.h>

extern CTxMemPool mempool;
extern std::unique_ptr<CCoinsViewCache> pcoinsTip;

bool CWallet::FundMintTransaction(CAmount& amountMin, CAmount& amountFound, std::vector<CTxIn>& ret) const
{
    amountFound = 0;

    std::unordered_set<const CWalletTx*, WalletTxHasher> spendableTx;
    {
        LOCK(cs_wallet);
        spendableTx = GetSpendableTXs();
    }

    for (auto out : spendableTx) {
        const auto& tx = out->tx;
        uint256 txHash = tx->GetHash();
        for (int n = 0; n < tx->vout.size(); n++) {
            CTxOut out = tx->vout[n];
            COutPoint wtx_out(txHash, n);
            if (IsInMempool(txHash)) {
                continue;
            }
            if (!IsOutputUnspent(wtx_out)) {
                continue;
            }
            if (!IsMine(out)) {
                continue;
            }
            if (GetUTXOConfirmations(wtx_out) < TOKEN_MINCONFS + 1) {
                continue;
            }
            if (IsOutputInMempool(wtx_out)) {
                continue;
            }
            CScript pk = out.scriptPubKey;
            CAmount inputValue = out.nValue;
            if (!pk.IsPayToToken() && !pk.IsChecksumData()) {
                amountFound += inputValue;
                CTxIn inputFound(COutPoint(txHash, n));
                ret.push_back(inputFound);
                if (amountFound >= amountMin) {
                    return true;
                }
            }
        }
    }
    return false;
}

bool CWallet::FundTokenTransaction(std::string& tokenname, CAmount& amountMin, CAmount& amountFound, std::vector<CTxIn>& ret) const
{
    amountFound = 0;

    std::map<uint256, CWalletTx> walletInst;
    {
         LOCK(cs_wallet);
         walletInst = mapWallet;
    }

    for (auto out : walletInst) {
        const auto& tx = out.second;
        uint256 txHash = tx.tx->GetHash();
        for (int n = 0; n < tx.tx->vout.size(); n++) {
            CTxOut out = tx.tx->vout[n];
            COutPoint wtx_out(txHash, n);
            if (!out.IsTokenOutput()) {
                LogPrint(BCLog::TOKEN, "%s: pass because not a token output (%s)\n", __func__, out.ToString());
                continue;
            }
            if (IsInMempool(txHash)) {
                LogPrint(BCLog::TOKEN, "%s: pass because tx is in mempool (%s)\n", __func__, out.ToString());
                continue;
            }
            if (!IsOutputUnspent(wtx_out)) {
                LogPrint(BCLog::TOKEN, "%s: pass because output is spent (%s)\n", __func__, out.ToString());
                continue;
            }
            if (!IsMine(out)) {
                LogPrint(BCLog::TOKEN, "%s: pass because output is not mine (%s)\n", __func__, out.ToString());
                continue;
            }
            if (GetUTXOConfirmations(wtx_out) < TOKEN_MINCONFS + 1) {
                LogPrint(BCLog::TOKEN, "%s: pass because insufficient confirms (%s)\n", __func__, out.ToString());
                continue;
            }
            if (IsOutputInMempool(wtx_out)) {
                LogPrint(BCLog::TOKEN, "%s: pass because output is in a mempool tx (%s)\n", __func__, out.ToString());
                continue;
            }
            CScript pk = out.scriptPubKey;
            CAmount inputValue = out.nValue;
            if (!pk.IsChecksumData()) {
                CToken token;
                if (!BuildTokenFromScript(pk, token)) {
                    continue;
                }
                LogPrint(BCLog::TOKEN, "%s: found %llu of %s\n", __func__, inputValue, token.getName());
                if (tokenname == token.getName()) {
                    amountFound += inputValue;
                    CTxIn inputFound(COutPoint(txHash, n));
                    ret.push_back(inputFound);
                    if (amountFound >= amountMin) {
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

bool CWallet::SignTokenTransaction(CMutableTransaction& rawTx, std::string& strError)
{
    strError = "No error";

    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    {
        LOCK(mempool.cs);
        CCoinsViewCache& viewChain = ::ChainstateActive().CoinsTip();
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        for (const CTxIn& txin : rawTx.vin) {
            view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }

    const CKeyStore& keystore = *this;

    int nHashType = SIGHASH_ALL;
    bool fHashSingle = ((nHashType & ~(SIGHASH_ANYONECANPAY)) == SIGHASH_SINGLE);

    UniValue vErrors(UniValue::VARR);
    const CTransaction txConst(rawTx);
    for (unsigned int i = 0; i < rawTx.vin.size(); i++) {

        CTxIn& txin = rawTx.vin[i];
        const Coin& coin = view.AccessCoin(txin.prevout);
        if (coin.IsSpent()) {
            strError = "Input not found or already spent";
            return false;
        }
        const CScript& prevPubKey = coin.out.scriptPubKey;
        const CAmount& amount = coin.out.nValue;

        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < rawTx.vout.size())) {
            SignSignature(keystore, prevPubKey, rawTx, i, amount, nHashType);
        }

        // ... and merge in other signatures:
        SignatureData sigdata = DataFromTransaction(rawTx, i, coin.out);
        ProduceSignature(keystore, MutableTransactionSignatureCreator(&rawTx, i, amount, nHashType), prevPubKey, sigdata);
        UpdateInput(txin, sigdata);

        ScriptError serror = SCRIPT_ERR_OK;
        if (!VerifyScript(txin.scriptSig, prevPubKey, STANDARD_SCRIPT_VERIFY_FLAGS, MutableTransactionSignatureChecker(&rawTx, i, amount), &serror)) {
            strError = ScriptErrorString(serror);
            return false;
        }
    }

    return true;
}

bool CWallet::GetUnconfirmedTokenBalance(CTxMemPool& pool, std::map<std::string, CAmount>& balances, std::string& strError)
{
    LOCK(mempool.cs);

    //! iterate through all txes in mempool
    for (const auto& l : pool.mapTx) {
        const CTransaction& mtx = l.GetTx();
        if (mtx.HasTokenOutput()) {
            for (unsigned int i = 0; i < mtx.vout.size(); i++) {
                CScript TokenScript = mtx.vout[i].scriptPubKey;
                if (TokenScript.IsPayToToken() && IsMine(mtx.vout[i])) {
                    CToken token;
                    if (!ContextualCheckToken(TokenScript, token, strError)) {
                        LogPrint(BCLog::TOKEN, "ContextualCheckToken returned with error %s\n", strError);
                        strError = "corrupt-invalid-existing-mempool";
                        return false;
                    }
                    std::string name = token.getName();
                    CAmount value = mtx.vout[i].nValue;
                    balances[name] += value;
                }
            }
        }
    }

    return true;
}

void CWallet::AbandonInvalidTransaction()
{
    if (::ChainstateActive().IsInitialBlockDownload()) {
        return;
    }

    LOCK(cs_wallet);

    auto locked_chain = chain().lock();
    for (std::pair<const uint256, CWalletTx>& item : mapWallet) {
        const uint256& txid = item.first;
        CWalletTx& wtx = item.second;
        int nDepth = wtx.GetDepthInMainChain(*locked_chain);
        if (nDepth == 0 && !wtx.isAbandoned()) {
            if (!AbandonTransaction(*locked_chain, txid)) {
                LogPrint(BCLog::TOKEN, "Failed to abandon tx %s\n", wtx.GetHash().ToString());
            }
        }
    }
}
