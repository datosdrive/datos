// Copyright (c) 2023 datos
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef POS_SIGNATURE_H
#define POS_SIGNATURE_H

#include <key.h>
#include <primitives/block.h>

using valtype = std::vector<unsigned char>;

bool SignBlockWithKey(CBlock& block, const CKey& key);
bool CheckBlockSignature(const CBlock& block);

#endif // POS_SIGNATURE_H
