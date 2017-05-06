#ifndef BYTE_ORDER_H
#define BYTE_ORDER_H

#include <cstdint>
#include <climits>
#include <stdint.h>

namespace bchain {

    struct host_byte_order {
        static bool is_big_endian( )
        {
            typedef const unsigned short const_ushort;
            static bool res =
                    (*reinterpret_cast<const_ushort *>("\001") == 0x0100);
            return res;
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
        static value_type value( value_type v )
        {
            return v;
        }

        template <typename U>
        static size_t write( value_type v, U *out )
        {
            const std::uint8_t *d = reinterpret_cast<const std::uint8_t *>(&v);
                  std::uint8_t *o = reinterpret_cast<      std::uint8_t *>(out);

            for( unsigned i=0; i < sizeof(value_type); i++ ) {
                o[i] = d[i];
            }
            return sizeof(value_type);
        }

        template <typename U>
        static value_type read( const U *in, size_t *len = nullptr )
        {
            value_type v;
            const std::uint8_t *o = reinterpret_cast<const std::uint8_t *>(in);
                  std::uint8_t *d = reinterpret_cast<      std::uint8_t *>(&v);
            for( unsigned i=0; i < sizeof(value_type); i++ ) {
                d[i] = o[i];
            }
            if( len ) {
                *len = sizeof(value_type);
            }
            return v;
        }

    };

    template <typename T>
    struct byte_order<T, true> {

        typedef T value_type;
        static  T value( value_type v )
        {
            value_type o;

            const std::uint8_t *d = reinterpret_cast<const std::uint8_t *>(&v);
                  std::uint8_t *m = reinterpret_cast<      std::uint8_t *>(&o);

            for( unsigned i=0; i < sizeof(value_type); i++ ) {
                m[i] = d[sizeof(value_type) - 1 - i];
            }

            return o;
        }

        template <typename U>
        static size_t write( value_type v, U *out )
        {
            const std::uint8_t *d = reinterpret_cast<const std::uint8_t *>(&v);
                  std::uint8_t *o = reinterpret_cast<      std::uint8_t *>(out);

            for( unsigned i=0; i < sizeof(value_type); i++ ) {
                o[sizeof(value_type) - i - 1] = d[i];
            }
            return sizeof(value_type);
        }

        template <typename U>
        static value_type read( const U *in, size_t *len = nullptr )
        {
            value_type v;
            const std::uint8_t *o = reinterpret_cast<const std::uint8_t *>(in);
                  std::uint8_t *d = reinterpret_cast<      std::uint8_t *>(&v);
            for( unsigned i=0; i < sizeof(value_type); i++ ) {
                d[i] = o[sizeof(value_type) - i - 1];
            }
            if( len ) {
                *len = sizeof(value_type);
            }
            return v;
        }
    };

    template<>
    struct byte_order<std::uint8_t, true>
    {
        typedef std::uint8_t value_type;
        static value_type value( value_type v )
        {
            return v;
        }

        template <typename U>
        static size_t write( value_type v, U *out )
        {
            *reinterpret_cast<std::uint8_t *>(out) = v;
            return sizeof(value_type);
        }

        template <typename U>
        static value_type read( const U *in, size_t *len = nullptr )
        {
            if( len ) {
                *len = sizeof(value_type);
            }
            return *reinterpret_cast<const std::uint8_t *>(in);
        }
    };

    template<>
    struct byte_order<std::uint8_t, false>
    {
        typedef std::uint8_t value_type;
        static value_type value( value_type v )
        {
            return v;
        }

        template <typename U>
        static size_t write( value_type v, U *out )
        {
            *reinterpret_cast<std::uint8_t *>(out) = v;
            return sizeof(value_type);
        }

        template <typename U>
        static value_type read( const U *in, size_t *len = nullptr )
        {
            if( len ) {
                *len = sizeof(value_type);
            }
            return *reinterpret_cast<const std::uint8_t *>(in);
        }
    };

    template<>
    struct byte_order<std::uint16_t, true> {
        typedef std::uint16_t value_type;
        static value_type value( value_type v )
        {
            return ( ( v & 0xff00 ) >> 8 ) |
                   ( ( v & 0x00ff ) << 8 ) ;
        }

        template <typename U>
        static size_t write( value_type v, U *out )
        {
            std::uint8_t *o = reinterpret_cast<std::uint8_t *>(out);
            o[1] =   v       & 0xFF;
            o[0] = ( v >> 8) & 0xFF;
            return sizeof(value_type);
        }

        template <typename U>
        static value_type read( const U *in, size_t *len = nullptr )
        {
            const std::uint8_t *o = reinterpret_cast<const std::uint8_t *>(in);
            if( len ) {
                *len = sizeof(value_type);
            }
            return static_cast<value_type>(o[0]) << 8 |
                   static_cast<value_type>(o[1])      ;
        }
    };

    template<>
    struct byte_order<std::uint32_t, true> {
        typedef std::uint32_t value_type;
        static value_type value( value_type v )
        {
            return ( ( v & 0xff000000 ) >> 24 ) |
                   ( ( v & 0x00ff0000 ) >>  8 ) |
                   ( ( v & 0x0000ff00 ) <<  8 ) |
                   ( ( v & 0x000000ff ) << 24 ) ;
        }

        template <typename U>
        static size_t write( value_type v, U *out )
        {
            std::uint8_t *o = reinterpret_cast<std::uint8_t *>(out);
            o[3] =   v         & 0xFF;
            o[2] = ( v >>  8 ) & 0xFF;
            o[1] = ( v >> 16 ) & 0xFF;
            o[0] = ( v >> 24 ) & 0xFF;
            return sizeof(value_type);
        }

        template <typename U>
        static value_type read( const U *in, size_t *len = nullptr )
        {
            const std::uint8_t *o = reinterpret_cast<const std::uint8_t *>(in);
            if( len ) {
                *len = sizeof(value_type);
            }
            return static_cast<value_type>(o[0]) << 24 |
                   static_cast<value_type>(o[1]) << 16 |
                   static_cast<value_type>(o[2]) <<  8 |
                   static_cast<value_type>(o[3])       ;
        }
    };

    template<>
    struct byte_order<std::uint64_t, true> {
        typedef std::uint64_t value_type;
        static
        value_type value( value_type v )
        {
            return ( ( v & 0xff00000000000000 ) >> 56) |
                   ( ( v & 0x00ff000000000000 ) >> 40) |
                   ( ( v & 0x0000ff0000000000 ) >> 24) |
                   ( ( v & 0x000000ff00000000 ) >>  8) |
                   ( ( v & 0x00000000ff000000 ) <<  8) |
                   ( ( v & 0x0000000000ff0000 ) << 24) |
                   ( ( v & 0x000000000000ff00 ) << 40) |
                   ( ( v & 0x00000000000000ff ) << 56) ;
        }

        template <typename U>
        static
        size_t write( value_type v, U *out )
        {
            std::uint8_t *o = reinterpret_cast<std::uint8_t *>(out);
            o[7] =   v         & 0xFF;
            o[6] = ( v >>  8 ) & 0xFF;
            o[5] = ( v >> 16 ) & 0xFF;
            o[4] = ( v >> 24 ) & 0xFF;
            o[3] = ( v >> 32 ) & 0xFF;
            o[2] = ( v >> 40 ) & 0xFF;
            o[1] = ( v >> 48 ) & 0xFF;
            o[0] = ( v >> 56 ) & 0xFF;
            return sizeof(value_type);
        }

        template <typename U>
        static
        value_type read( const U *in, size_t *len = nullptr )
        {
            const std::uint8_t *o = reinterpret_cast<const std::uint8_t *>(in);
            if( len ) {
                *len = sizeof(value_type);
            }
            return static_cast<value_type>(o[0]) << 56 |
                   static_cast<value_type>(o[1]) << 48 |
                   static_cast<value_type>(o[2]) << 40 |
                   static_cast<value_type>(o[3]) << 32 |
                   static_cast<value_type>(o[4]) << 24 |
                   static_cast<value_type>(o[5]) << 16 |
                   static_cast<value_type>(o[6]) <<  8 |
                   static_cast<value_type>(o[7])       ;
        }

    };

}

#endif // BYTE_ORDER_H
