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
        typedef byte_order<std::uint16_t, Val> bytes16;
        typedef byte_order<std::uint32_t, Val> bytes32;
        typedef byte_order<std::uint64_t, Val> bytes64;
        typedef varint<Val>                    bytesv;

        v16.value  = &bytes16::value;
        v16.write  = &bytes16::template write<std::uint8_t>;
        v16.read   = &bytes16::template read<std::uint8_t>;

        v32.value  = &bytes32::value;
        v32.write  = &bytes32::template write<std::uint8_t>;
        v32.read   = &bytes32::template read<std::uint8_t>;

        v64.value  = &bytes64::value;
        v64.write  = &bytes64::template write<std::uint8_t>;
        v64.read   = &bytes64::template read<std::uint8_t>;

        vvar.value = &bytesv::value;
        vvar.write = &bytesv::template write<std::uint8_t>;
        vvar.read  = &bytesv::template read<std::uint8_t>;
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

    val<std::uint16_t> v16;
    val<std::uint32_t> v32;
    val<std::uint64_t> v64;
    val<std::uint64_t> vvar;

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
    little_endian le;

    auto l1 = le.vvar.write( 12345, bo );
    auto l2 = le.vvar.write( 12345678, bo + l1 );

    std::cout << l1 << " " << l2 << "\n";

    std::cout << le.vvar.read( bo, &l1 ) << std::endl;
    std::cout << le.vvar.read( bo + l1, &l2 ) << std::endl;

    return 0;
}

