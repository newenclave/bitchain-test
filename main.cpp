#include <iostream>
#include <string>
#include <climits>
#include <sys/types.h>
#include <arpa/inet.h>

#include <functional>

#include "openssl/sha.h"

#include "byte_order.h"
#include "varint.h"

using namespace bchain;

struct endian
{
    endian( bool bigendian )
    {
        if( bigendian ) {
            if( host_byte_order::is_big_endian( ) ) {
                value16 = &byte_order<std::uint16_t, false>::value;
                value32 = &byte_order<std::uint32_t, false>::value;
                value64 = &byte_order<std::uint64_t, false>::value;
            } else {
                value16 = &byte_order<std::uint16_t,  true>::value;
                value32 = &byte_order<std::uint32_t,  true>::value;
                value64 = &byte_order<std::uint64_t,  true>::value;
            }
        } else {
            if( host_byte_order::is_big_endian( ) ) {
                value16 = &byte_order<std::uint16_t,  true>::value;
                value32 = &byte_order<std::uint32_t,  true>::value;
                value64 = &byte_order<std::uint64_t,  true>::value;
            } else {
                value16 = &byte_order<std::uint16_t, false>::value;
                value32 = &byte_order<std::uint32_t, false>::value;
                value64 = &byte_order<std::uint64_t, false>::value;
            }
        }
    }

    typedef std::uint16_t ( * hton16_type )( std::uint16_t );
    typedef std::uint32_t ( * hton32_type )( std::uint32_t );
    typedef std::uint64_t ( * hton64_type )( std::uint64_t );

    hton16_type value16;
    hton32_type value32;
    hton64_type value64;
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

    std::uint8_t bo[sizeof(std::uint64_t) * 2];

    varint<false> ll;
    varint<true>  bb;

    auto lw = ll.write( 12345, bo );
    auto bw = bb.write( 123456, bo + lw );

    size_t len = 0;
    std::cout << ll.read(&bo[len], &len) << "\n";
    std::cout << bb.read(&bo[len], &len) << "\n";

    std::cout << lw << " " << bw << "\n";

    return 0;
}

