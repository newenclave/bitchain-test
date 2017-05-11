#ifndef VARINT_H
#define VARINT_H

#include <string>

#include "byte_order.h"
#include "etool/details/byte_order.h"

namespace bchain {

    struct varint {

        typedef std::uint64_t size_type;

        static const std::size_t min_length = sizeof(std::uint8_t);
        static const std::size_t max_length = sizeof(size_type) + min_length;

        using u16_little = etool::details::byte_order_little<std::uint16_t>;
        using u32_little = etool::details::byte_order_little<std::uint32_t>;
        using u64_little = etool::details::byte_order_little<std::uint64_t>;

        enum prefix_value {

            PREFIX_VARINT_MIN = 0xFD,

            PREFIX_VARINT16   = 0xFD,
            PREFIX_VARINT32   = 0xFE,
            PREFIX_VARINT64   = 0xFF,

            PREFIX_VARINT_MAX = 0xFF,
        };

        static
        std::size_t len_by_prefix( std::uint8_t prefix )
        {
            switch (prefix) {
            case PREFIX_VARINT64:
                return sizeof(std::uint64_t) + min_length;
            case PREFIX_VARINT32:
                return sizeof(std::uint32_t) + min_length;
            case PREFIX_VARINT16:
                return sizeof(std::uint16_t) + min_length;
            default:
                break;
            }
            return min_length;
        }

        static
        std::size_t result_length( size_type len )
        {
            if( len < PREFIX_VARINT_MIN ) {
                return sizeof(std::uint8_t);
            } else if( len <= 0xFFFF ) {
                return sizeof(std::uint16_t) + min_length;
            } else if( len <= 0xFFFFFFFF ) {
                return sizeof(std::uint32_t) + min_length;
            } else {
                return sizeof(std::uint64_t) + min_length;
            }
        }

        static
        std::size_t packed_length( const void *data, size_t len )
        {
            if( len > 0 ) {
                auto u8 = *static_cast<const std::uint8_t *>(data);
                auto res = len_by_prefix(u8);
                return (res >= len) ? res : 0;
            }
            return 0;
        }


        template <typename U>
        static
        std::size_t write( size_type size, U *result )
        {
            std::uint8_t *res  = reinterpret_cast<std::uint8_t *>(result);
            if( size < PREFIX_VARINT_MIN ) {
                res[0] = static_cast<std::uint8_t>(size);
                return min_length;
            } else if( size <= 0xFFFF ) {
                res[0] = static_cast<std::uint8_t>(PREFIX_VARINT16);
                return u16_little::write( size, &res[1] ) + min_length;
            } else if( size <= 0xFFFFFFFF ) {
                res[0] = static_cast<std::uint8_t>(PREFIX_VARINT32);
                return u32_little::write( size, &res[1] ) + min_length;
            } else {
                res[0] = static_cast<std::uint8_t>(PREFIX_VARINT64);
                return u64_little::write( size, &res[1] ) + min_length;
            }
        }

        static
        void append( size_type size, std::string &res )
        {
            std::size_t last = res.size( );
            res.resize(last + result_length(size));
            write( size, &res[last] );
        }

        template <typename U>
        static
        size_type read( const U *data, size_t length, size_t *len )
        {
            const std::uint8_t *d = static_cast<const std::uint8_t *>(data);
            length = length * sizeof(U);
            std::size_t len_ = len_by_prefix( *d );

            if( length < len_ ) {
                return 0;
            }

            size_type res_ = 0;

            if( len_ == min_length ) {
                res_ = static_cast<size_type>(*d);
             } else {
                switch (*d) {
                case PREFIX_VARINT16:
                    res_ = u16_little::read( d + min_length );
                    break;
                case PREFIX_VARINT32:
                    res_ = u32_little::read( d + min_length );
                    break;
                case PREFIX_VARINT64:
                    res_ = u64_little::read( d + min_length );
                    break;
                default:
                    break;
                }
            }

            if( len ) {
                *len = len_;
            }

            return res_;
        }

    };

}

#endif // VARINT_H
