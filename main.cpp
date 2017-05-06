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

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>

#include "etool/details/byte_order.h"
#include "etool/dumper/dump.h"

#include <memory.h>

#include "catch/catch.hpp"

using namespace bchain;
using namespace etool;

namespace {

}

int main( )
{

    std::string out;

    serializer::append_uint<std::uint32_t>(out, 0x68f7a38b  );
    serializer::append_string(             out, "FooBar", 10);
    serializer::append_uint<std::uint16_t>(out, 0xee12      );

    dumper::make<>::all( out.c_str( ), 4, std::cout );
    std::cout << "\n";
    dumper::make<>::all( out.c_str( ) + 4, 10, std::cout );
    std::cout << "\n";
    dumper::make<>::all( out.c_str( ) + 14, 2, std::cout );

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

    return 0;
}

