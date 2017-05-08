#ifndef PARSER_H
#define PARSER_H


#include <algorithm>

#include "hash.h"
#include "base58.h"

#include "etool/details/byte_order.h"
#include "etool/slices/memory.h"

#include "varint.h"

namespace bchain {

    struct parser {

        template <typename T>
        using res_pair = std::pair<T, bool>;

        static
        res_pair<std::uint64_t> read_varint( const void *data,
                                   size_t len, size_t *pos )
        {
            auto u8 = static_cast<const std::uint8_t *>(data);
            size_t shift = 0;
            auto res = varint::read( &u8[*pos], len - *pos, &shift );
            bool read = false;
            if( shift > 0 ) {
                *pos += shift;
                read = true;
            }
            return std::make_pair(res, read);
        }

        template <typename IntT>
        static
        res_pair<IntT> read_int( const void *data,
                                 size_t len, size_t *pos )
        {
            using ulittle = etool::details::byte_order_little<IntT>;

            auto u8 = static_cast<const std::uint8_t *>(data);
            if( (len - *pos) >= sizeof(IntT) ) {
                IntT res = ulittle::read( &u8[*pos] );
                *pos += sizeof(IntT);
                return std::make_pair(res, true);
            }
            return std::make_pair(IntT( ), false);
        }

        static
        res_pair<std::string> read_string( const void *data,
                                           size_t len, size_t *pos,
                                           size_t string_len )
        {
            auto u8 = static_cast<const char *>(data);
            if( len - *pos >= string_len ) {
                std::string res( &u8[*pos], &u8[*pos + string_len] );
                *pos += string_len;
                return std::make_pair(std::move(res), true);
            }
            return std::make_pair(std::string( ), false);
        }
    };
}

#endif // PARSER_H
