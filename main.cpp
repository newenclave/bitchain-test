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
#include "parser.h"
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

    uint8_t pub_bytes_[33] = {
        0x02,
        0x82, 0x00, 0x6e, 0x93, 0x98, 0xa6, 0x98, 0x6e,
        0xda, 0x61, 0xfe, 0x91, 0x67, 0x4c, 0x3a, 0x10,
        0x8c, 0x39, 0x94, 0x75, 0xbf, 0x1e, 0x73, 0x8f,
        0x19, 0xdf, 0xc2, 0xdb, 0x11, 0xdb, 0x1d, 0x28
    };

    uint8_t bytes[] = {
        0xfd, 0x0a, 0x00, 0xe3,
        0x03, 0x41, 0x8b, 0xa6,
        0x20, 0xe1, 0xb7, 0x83,
        0x60
    };

    uint8_t bytes_for_base[] = {
        0x73, 0xb7, 0xb2, 0x1c, 0x26, 0xc1, 0x7b, 0x72,
        0x24, 0xdb, 0x60, 0xff, 0x7d, 0xd7, 0xe4, 0xc6,
        0x48, 0xf5, 0x6c, 0x70, 0x24, 0x4e, 0xa6, 0xc4,
        0xb6, 0x94, 0x1c, 0x0c, 0xbd, 0x16, 0x8c, 0x30
    };

    const std::string message = "This is a very confidential message\n";
}

// Wallet Import Format
struct wif {

    static
    std::string create( const crypto::ec_key &k,
                        std::uint8_t prefix, bool compress_public )
    {
        auto private_bytes = k.get_private_bytes( );
        return create( private_bytes, prefix, compress_public );
    }

    static
    std::string create( const std::string &private_bytes,
                        std::uint8_t prefix, bool compress_public )
    {
        using cu8 = const std::uint8_t;
        auto u8data = reinterpret_cast<cu8 *>(private_bytes.c_str( ));
        return create( u8data, private_bytes.size( ), prefix, compress_public );
    }

    static
    std::string create( const std::uint8_t *priv_bytes, size_t plen,
                        std::uint8_t prefix, bool compress_public )
    {
        std::string res;

        res.push_back( static_cast<char>(prefix) );
        res.append( &priv_bytes[0], &priv_bytes[plen] );

        if( compress_public ) {
            res.push_back( 0x01 );
        }

        hash::hash256::digit_block digit;
        hash::hash256::get( digit, res.c_str( ), res.size( ) );
        res.append( &digit[0], &digit[4] );

        return base58::encode( res );
    }
};

// pay-to-public-key-hash
struct p2pkh {

    static
    std::string create( crypto::ec_key &k, std::uint8_t prefix )
    {
        auto pub_bytes = k.get_public_bytes( );
        return create( pub_bytes, prefix );
    }

    static
    std::string create( const std::string &pub_bytes, std::uint8_t prefix )
    {
        using cu8 = const std::uint8_t;
        auto u8data = reinterpret_cast<cu8 *>(pub_bytes.c_str( ));
        return create( u8data, pub_bytes.size( ), prefix );
    }

    static
    std::string create( const std::uint8_t *pub_bytes, size_t len,
                        std::uint8_t prefix )
    {
        std::string res;
        res.push_back( static_cast<char>(prefix) );

        hash::hash160::append( pub_bytes, len, res );

        hash::hash256::digit_block digit;
        hash::hash256::get( digit, res.c_str( ), res.size( ) );
        res.append( &digit[0], &digit[4] );

        return base58::encode( res );
    }
};

int test( )
{
    auto k = crypto::ec_key::create_private(priv_bytes, sizeof(priv_bytes));
    //auto k = crypto::ec_key::create_public(pub_bytes, sizeof(pub_bytes));

    k.set_conv_compressed( true );
    auto pb = k.get_public_bytes( );
    k.set_conv_compressed( false );
    auto pbu = k.get_public_bytes( );

    dumper::make<>::all( pb.c_str( ), pb.size( ),
                         std::cout << "Compressed: \n") << "\n";

    dumper::make<>::all( pbu.c_str( ), pbu.size( ),
                         std::cout << "Uncompressed: \n") << "\n";


    std::cout << k.get_conv_compressed( ) << "\n";

    return 0;
}

int main( )
{
    auto base = base58::encode( bytes_for_base, sizeof(bytes_for_base) );
    dumper::make<>::all(base.c_str( ), base.size( ),
                        std::cout << "Base58: \n") << "\n";

    auto addr = hash::hash160::get_string(pub_bytes, sizeof(pub_bytes));
    addr.insert(addr.begin(), 0x6f);

    auto chcked = base58::encode_check( addr.c_str( ), addr.size( ) );
    auto wif    = wif::create( priv_bytes, sizeof(priv_bytes), 0xef, true );
    auto p2pkn  = p2pkh::create( pub_bytes, sizeof(pub_bytes), 0x6f );

    dumper::make<>::all(chcked.c_str( ), chcked.size( ),
                        std::cout << "Checked: \n") << "\n";

    std::cout << "WIF: " << wif << "\n";
    std::cout << "p2p: " << p2pkn << "\n";

    auto dec = base58::decode( base );
    dumper::make<>::all(dec.c_str( ), dec.size( ),
                        std::cout << "Decode: \n") << "\n";

    std::cout << (std::string(&bytes_for_base[0],
                              &bytes_for_base[sizeof(bytes_for_base)]) == dec)
            << "\n";

}

int sign( )
{
    //auto k = crypto::ec_key::generate( );
    auto k  = crypto::ec_key::create_private( priv_bytes, sizeof(priv_bytes) );
    auto pk = crypto::ec_key::create_public(  pub_bytes,  sizeof(pub_bytes) );

    auto digest    = hash::sha256::get_string( message.c_str( ),
                                               message.size( ) );
    auto signature = crypto::signature::sign( digest.c_str( ),
                                              digest.size( ), k.get( ) );

    auto der = signature.to_der( k.get( ) );
    auto sig = crypto::signature::from_der( der );

    dumper::make<>::all(der.c_str( ), der.size( ),
                        std::cout << "DER: \n") << "\n";

    auto verified = sig.verify( digest.c_str( ), digest.size( ), pk.get( ) );

    std::cout << verified << "\n";

    dumper::make<>::all(digest.c_str( ), digest.size( ),
                        std::cout << "SHA256: \n") << "\n";

    return 0;
}

