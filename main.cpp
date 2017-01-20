#include <iostream>
#include <string>
#include <climits>
#include <sys/types.h>
#include <arpa/inet.h>

#include <functional>

#include "openssl/sha.h"
#include "openssl/ripemd.h"

#include "byte_order.h"
#include "varint.h"

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

void sha256_digit( std::uint8_t *out, char *message, size_t len )
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update( &ctx, message, len );
    SHA256_Final( out, &ctx );
}

void ripemd169_digit( std::uint8_t *out, char *message, size_t len )
{
    RIPEMD160_CTX ctx;
    RIPEMD160_Init(&ctx);
    RIPEMD160_Update( &ctx, message, len );
    RIPEMD160_Final( out, &ctx );
}

int main( )
{
    uint8_t bytes[] = {
        0x13, 0x9c, 0xfd, 0x7d,
        0x80, 0x44, 0x6b, 0xa2,
        0x20, 0xcc
    };

    typedef struct {
        uint16_t fixed1;
        uint64_t var2;
        uint32_t fixed3;
        uint8_t fixed4;
    } foo_t;

    little_endian le;
    size_t len = 0;
    size_t tmp = 0;
    foo_t decoded;

    decoded.fixed1 = le.v16.read( &bytes[len], &tmp );
    len += tmp;
    decoded.var2   = le.var.read( &bytes[len], &tmp );
    len += tmp;
    decoded.fixed3 = le.v32.read( &bytes[len], &tmp );
    len += tmp;
    decoded.fixed4 = le.v8.read( &bytes[len], &tmp );

    std::cout << std::hex
              << decoded.fixed1 << " "
              << decoded.var2   << " "
              << decoded.fixed3 << " "
              << decoded.fixed4 << " "
              << "\n";

    return 0;
}

