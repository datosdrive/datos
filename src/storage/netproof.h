// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_STORAGE_NETPROOF_H
#define BITCOIN_STORAGE_NETPROOF_H

#include <net.h>
#include <storage/proof.h>
#include <storage/util.h>
#include <uint256.h>

#include <cstddef>
#include <list>
#include <type_traits>

class CConnman;

// CNetworkProof: encapsulates CProof with blockheight and signed hash
class CNetworkProof {
public:
    int height;
    CProof proof;
    uint256 hash;
    std::vector<unsigned char> vchProofSig;

    CNetworkProof()
    {
        SetNull();
    }

    bool IsEmpty()
    {
        if (sizeof(*this) == 88)
            return true;
        return false;
    }

    bool Check()
    {
        if (IsEmpty())
            return true;
        int nodes = 0;
        for (struct StorageNode& l : proof.nodes) ++nodes;
        return nodes > 0;
    }

    void CalculateHash()
    {
        uint256 h;
        CSHA256 sha256;
        sha256.Write((const unsigned char*)&height, sizeof(int));
        for (struct StorageNode& l : proof.nodes) {
            const uint256 i = l.GetHash();
            sha256.Write(i.data(), 32);
        }
        sha256.Finalize(h.begin());
        this->hash = h;
    }

    SERIALIZE_METHODS(CNetworkProof, obj)
    {
        READWRITE(obj.height);
        READWRITE(obj.proof);
        READWRITE(obj.hash);
        READWRITE(obj.vchProofSig);
    }

    void SetNull()
    {
        height = 0;
        hash.SetNull();
        vchProofSig.clear();
    }

    void ToString()
    {
        char ipaddr[14];
        printf("height %d\n", height);
        for (auto& entry : proof.nodes) {
            memset(ipaddr, 0, sizeof(ipaddr));
            uint32_to_ip(entry.ip, ipaddr);
            printf("csid %d [srvip %s, mode %d, status %d, registered %d, load %d, chunks %d, errcnt %d, totalspace %dGiB]\n",
                entry.id, ipaddr, entry.mode, entry.stat, entry.reg, entry.load, entry.chunks, entry.errcnt, entry.space);
        }
    }

    void Relay(CConnman& connman) const
    {
        CInv inv(MSG_NETPROOF, hash);
        connman.RelayInv(inv);
    }
};

#endif // BITCOIN_STORAGE_NETPROOF_H
