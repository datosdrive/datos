// Copyright (c) 2023 datos
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TOKEN_TOKEN_H
#define TOKEN_TOKEN_H

#include <amount.h>
#include <logging.h>
#include <pubkey.h>
#include <script/script.h>
#include <serialize.h>
#include <token/util.h>
#include <util/strencodings.h>

class CScript;
class CPubKey;

//! const for token parameters
const int TOKEN_IDRANGE = 16;
const int TOKEN_MINCONFS = 1;
const int TOKENNAME_MINLEN = 3;
const int TOKENNAME_MAXLEN = 12;
const CAmount TOKEN_VALUEMAX = std::numeric_limits<int>::max();

//! ctoken class definition
class CToken {

private:
    uint8_t version;
    uint16_t type;
    uint64_t uid;
    std::string name;
    uint256 origintx;

public:
    static const uint8_t CURRENT_VERSION = 0x01;

    enum {
        NONE,
        ISSUANCE,
        TRANSFER
    };

    CToken()
    {
        version = CToken::CURRENT_VERSION;
        type = CToken::NONE;
        uid = uint64_t(0);
        name.clear();
        origintx = uint256();
    }

    SERIALIZE_METHODS(CToken, obj)
    {
        READWRITE(obj.version);
        READWRITE(obj.type);
        READWRITE(obj.uid);
        READWRITE(obj.name);
        READWRITE(obj.origintx);
    }

    std::string ToString() const
    {
        std::stringstream s;
        s << strprintf("CToken(version=0x%02x, type=0x%02x, uid=0x%08x, name='%s', origintx='%s')\n",
                       version, type, uid, name, origintx.ToString());
        return s.str();
    }

    uint64_t getId() { return uid; }
    uint16_t getType() { return type; }
    uint8_t getVersion() { return version; }
    std::string getName() { return name; }
    uint256 getOriginTx() { return origintx; }

    void setId(uint64_t thisId) { uid = thisId; }
    void setType(uint16_t thisType) { type = thisType; }
    void setVersion(uint8_t thisVersion) { version = thisVersion; }
    void setName(std::string thisName) { name = thisName; }
    void setOriginTx(uint256 hash) { origintx = hash; }

    bool isIssuance() { return getType() == CToken::ISSUANCE; }
    bool isTransfer() { return getType() == CToken::TRANSFER; }

    bool operator==(CToken& other)
    {
        return (getId() == other.getId() && getName() == other.getName());
    }
};

void BuildChecksumScript(CScript& ChecksumScript, uint160& ChecksumInput);
bool DecodeChecksumScript(CScript& ChecksumScript, uint160& ChecksumOutput);
void BuildTokenScript(CScript& TokenScript, const uint8_t version, const uint16_t type, uint64_t& identifier, std::string& name, CScript& scriptPubKey);
bool DecodeTokenScript(CScript& TokenScript, uint8_t& version, uint16_t& type, uint64_t& identifier, std::string& name, CPubKey& ownerPubKey, bool debug = false);
bool GetTokenidFromScript(CScript& TokenScript, uint64_t& id, bool debug = false);
bool BuildTokenFromScript(CScript& TokenScript, CToken& token, bool debug = false);

#endif // TOKEN_TOKEN_H
