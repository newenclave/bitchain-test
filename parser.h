#ifndef PARSER_H
#define PARSER_H


#include <algorithm>

#include "hash.h"
#include "base58.h"

#include "etool/details/byte_order.h"
#include "etool/slices/memory.h"
#include "etool/details/result.h"

#include "varint.h"

namespace bchain {

    struct parser {

        template <typename T>
        using result_type = etool::detail::result<T, const char *>;
        using data_slice  = etool::slices::memory<const std::uint8_t>;

        class state {

            state( const void *data, size_t len )
                :slice_(static_cast<const std::uint8_t *>(data), len)
                ,shift_(0)
            { }

            void inc_shift( size_t val )
            {
                shift_ += val;
            }

            const std::uint8_t *get(  ) const
            {
                return slice_.get( ) + shift_;
            }

            size_t size( ) const
            {
                return slice_.size( ) - shift_;
            }

        private:
            data_slice slice_;
            size_t     shift_;
        };

        static
        result_type<std::uint64_t> read_varint( const void *data,
                                                size_t len, size_t *pos )
        {
            using res_type = result_type<std::uint64_t>;
            auto u8 = static_cast<const std::uint8_t *>(data);
            size_t shift = 0;
            auto res = varint::read( &u8[*pos], len - *pos, &shift );
            if( shift > 0 ) {
                *pos += shift;
                return res_type::ok(res);
            }
            return res_type::fail("Not enough data");
        }

        template <typename IntT>
        static
        result_type<IntT> read_uint( const void *data,
                                     size_t len, size_t *pos )
        {
            using res_type = result_type<IntT>;
            using ulittle = etool::details::byte_order_little<IntT>;

            auto u8 = static_cast<const std::uint8_t *>(data);
            if( (len - *pos) >= sizeof(IntT) ) {
                IntT res = ulittle::read( &u8[*pos] );
                *pos += sizeof(IntT);
                return res_type::ok(res);
            }
            return res_type::fail("Not enough data");
        }

        static
        result_type<std::string> read_string( const void *data,
                                              size_t len, size_t *pos,
                                              size_t string_len )
        {
            using res_type = result_type<std::string>;
            auto u8 = static_cast<const char *>(data);
            if( len - *pos >= string_len ) {
                std::string res( &u8[*pos], &u8[*pos + string_len] );
                *pos += string_len;
                return res_type::ok(res);
            }
            return res_type::fail("Not enough data");
        }
    };
}

#endif // PARSER_H
