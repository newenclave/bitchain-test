#include <iostream>
#include <string>
#include <sys/types.h>
#include <arpa/inet.h>

#include <functional>

#define IS_BIG_ENDIAN    (*(const unsigned short *)("\000\001") == 1)
#define IS_LITTLE_ENDIAN (*(const unsigned short *)("\000\001") == 0)
#define IS_NETWORK_ORDER IS_BIG_ENDIAN

struct host_byte_order {
    static bool is_big_endian( )
    {
        typedef const unsigned short const_ushort;
        return (*reinterpret_cast<const_ushort *>("\001") == 0x0100);
    }

    static bool is_little_endian( )
    {
        return !is_big_endian( );
    }
};

template<typename T, bool Swap>
struct byte_order;

template<typename T>
struct byte_order<T, false> {
    typedef T value_type;
    static T value( T v )
    {
        return v;
    }
};

template <typename T>
struct byte_order<T, true> {

    typedef T value_type;
    static  T value( T v )
    {
        const std::uint8_t *d = reinterpret_cast<const std::uint8_t *>(&v);

        std::uint8_t block[sizeof(value_type)];

        for( unsigned i=0; i < sizeof(value_type); i++ ) {
            block[i] = d[sizeof(value_type) - 1 - i];
        }
        return *reinterpret_cast<T *>(&block[0]);
    }
};

template<>
struct byte_order<std::uint16_t, true> {
    typedef std::uint16_t value_type;
    static value_type value( value_type v )
    {
        return (   v          >> 8 ) |
               ( ( v & 0xff ) << 8 ) ;
    }

};

template<>
struct byte_order<std::uint32_t, true> {
    typedef std::uint32_t value_type;
    static value_type value( value_type v )
    {
        return (   v              >> 24 ) |
               ( ( v & 0xff0000 ) >>  8 ) |
               ( ( v & 0x00ff00 ) <<  8 ) |
               ( ( v & 0x0000ff ) << 24 ) ;
    }
};

template<>
struct byte_order<std::uint64_t, true> {
    typedef std::uint64_t value_type;
    static value_type value( value_type v )
    {
        return (   v                      >> 56) |
               ( ( v & 0xff000000000000 ) >> 40) |
               ( ( v & 0x00ff0000000000 ) >> 24) |
               ( ( v & 0x0000ff00000000 ) >>  8) |
               ( ( v & 0x000000ff000000 ) <<  8) |
               ( ( v & 0x00000000ff0000 ) << 24) |
               ( ( v & 0x0000000000ff00 ) << 40) |
               ( ( v & 0x000000000000ff ) << 56) ;
    }
};

struct net_endian
{
    net_endian( bool bigendian )
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

struct big_endian: public net_endian {
    big_endian( )
        :net_endian(true)
    { }
};

struct little_endian: public net_endian {
    little_endian( )
        :net_endian(false)
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
    std::string   ser(15, '\0');
    little_endian le;

    std::uint8_t  n8  = 0x01;
    std::uint16_t n16 = 0x4523;
    std::uint32_t n32 = 0xcdab8967;
    std::uint64_t n64 = 0xdebc9a78563412ef;

    ser[0] = n8;
    *(uint16_t *)(&ser[1]) = le.value16(n16);
    *(uint32_t *)(&ser[3]) = le.value32(n32);
    *(uint64_t *)(&ser[7]) = le.value64(n64);

    bintohex(std::cout, ser);

    std::cout << std::endl;

    return 0;
}

