#include <iostream>
#include <string>
#include <climits>
#include <sys/types.h>
#include <arpa/inet.h>

#include <functional>
#include <memory>

#include "openssl/sha.h"
#include "openssl/ripemd.h"

#include "byte_order.h"
#include "varint.h"
#include "base58.h"
#include "hash.h"
#include "crypto.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>

#include <etool/details/byte_order.h>

#include <memory.h>

#include "catch/catch.hpp"

using namespace bchain;

int main( )
{

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

    uint8_t digest[32];
    const char message[] = "This is a very confidential message\n";

    auto kpriv = crypto::key_pair::create_private( priv_bytes, sizeof(priv_bytes) );
    auto kpub  = crypto::key_pair::create_public( pub_bytes, sizeof(pub_bytes) );

    hash::sha256::get( digest, message, strlen(message) );

    auto ss = crypto::signature::sign( digest, 32, kpriv.get( ) );

    auto chk = ss.check( digest, 32, kpub.get( ) );

    std::cout << chk << "\n";


    std::cout << base58::encode_check( "Hello!", 6 ) << "\n";


    return 0;
}

