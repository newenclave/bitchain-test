#include <iostream>
#include <string>
#include <climits>

#include <functional>
#include <memory>

#include "openssl/sha.h"
#include "openssl/ripemd.h"

#include "varint.h"
#include "base58.h"
#include "hash.h"
#include "crypto.h"
#include "serializer.h"
#include "varint.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>

#include "etool/details/byte_order.h"
#include "etool/dumper/dump.h"
#include "etool/sizepack/blockchain_varint.h"

#include <memory.h>

#include "catch/catch.hpp"

using namespace bchain;
using namespace bchain::hash;
using namespace etool;

namespace {

    uint8_t priv_bytes[32] = {
        0x16, 0x26, 0x07, 0x83, 0xe4, 0x0b, 0x16, 0x73,
        0x16, 0x73, 0x62, 0x2a, 0xc8, 0xa5, 0xb0, 0x45,
        0xfc, 0x3e, 0xa4, 0xaf, 0x70, 0xf7, 0x27, 0xf3,
        0xf9, 0xe9, 0x2b, 0xdd, 0x3a, 0x1d, 0xdc, 0x42
    };

    uint8_t pub_bytes[33] = {
        0x02,
        0x82, 0x00, 0x6e, 0x93, 0x98, 0xa6, 0x98, 0x6e,
        0xda, 0x61, 0xfe, 0x91, 0x67, 0x4c, 0x3a, 0x10,
        0x8c, 0x39, 0x94, 0x75, 0xbf, 0x1e, 0x73, 0x8f,
        0x19, 0xdf, 0xc2, 0xdb, 0x11, 0xdb, 0x1d, 0x28
    };

    using u16l   = details::byte_order<std::uint16_t, etool::details::endian::LITTLE>;
    using u32l   = details::byte_order<std::uint32_t, etool::details::endian::LITTLE>;
    using u64l   = details::byte_order<std::uint64_t, etool::details::endian::LITTLE>;

    uint8_t bytes[] = {
        0xfd, 0x0a, 0x00, 0xe3,
        0x03, 0x41, 0x8b, 0xa6,
        0x20, 0xe1, 0xb7, 0x83,
        0x60
    };
}

int main( )
{

    std::string data;
    size_t res = 0;
    auto len = varint::read(bytes, 13, &res);

    data.assign( (char *)&bytes[res], len );

    std::cout << res << " " << len << "\n";
    std::cout << data << "\n";

    return 0;
}

