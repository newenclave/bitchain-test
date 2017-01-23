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

#include <memory.h>

using namespace bchain;

struct endian
{
private:

    template <typename T>
    struct val{

        typedef T      (* convert_type)(T);
        typedef size_t (* write_type)(T, std::uint8_t *);
        typedef T      (* read_type)(const std::uint8_t *, size_t *);

        convert_type  value;
        write_type    write;
        read_type     read;
    };

    template <bool Val>
    void set( )
    {
        typedef byte_order<std::uint8_t,  Val> bytes8;
        typedef byte_order<std::uint16_t, Val> bytes16;
        typedef byte_order<std::uint32_t, Val> bytes32;
        typedef byte_order<std::uint64_t, Val> bytes64;
        typedef varint<Val>                    bytesv;

        v8.value  = &bytes8::value;
        v8.write  = &bytes8::template write<std::uint8_t>;
        v8.read   = &bytes8::template read<std::uint8_t>;

        v16.value  = &bytes16::value;
        v16.write  = &bytes16::template write<std::uint8_t>;
        v16.read   = &bytes16::template read<std::uint8_t>;

        v32.value  = &bytes32::value;
        v32.write  = &bytes32::template write<std::uint8_t>;
        v32.read   = &bytes32::template read<std::uint8_t>;

        v64.value  = &bytes64::value;
        v64.write  = &bytes64::template write<std::uint8_t>;
        v64.read   = &bytes64::template read<std::uint8_t>;

        var.value = &bytesv::value;
        var.write = &bytesv::template write<std::uint8_t>;
        var.read  = &bytesv::template read<std::uint8_t>;
    }

public:

    endian( bool bigendian )
    {
        if( bigendian ) {
            if( host_byte_order::is_big_endian( ) ) {
                set<false>( );
            } else {
                set<true>( );
            }
        } else {
            if( host_byte_order::is_big_endian( ) ) {
                set<true>( );
            } else {
                set<false>( );
            }
        }
    }

    val<std::uint8_t>  v8;
    val<std::uint16_t> v16;
    val<std::uint32_t> v32;
    val<std::uint64_t> v64;
    val<std::uint64_t> var;

};

struct big_endian: public endian {
    big_endian( )
        :endian(true)
    { }
};

struct little_endian: public endian {
    little_endian( )
        :endian(false)
    { }
};

std::ostream &bintohex( std::ostream &o, const std::string &data )
{
    o << std::hex;
    for( auto a: data ) {
        o << (std::uint16_t)(std::uint8_t)(a);
    }
    return o;
}


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

    return 0;
}

