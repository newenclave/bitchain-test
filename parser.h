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

        public:
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
        result_type<std::uint64_t> read_varint( state &st )
        {
            using res_type = result_type<std::uint64_t>;
            size_t shift = 0;
            auto res = varint::read( st.get( ), st.size( ), &shift );
            if( shift > 0 ) {
                st.inc_shift( shift );
                return res_type::ok(res);
            }
            return res_type::fail("Not enough data");
        }

        template <typename IntT>
        static
        result_type<IntT> read_uint( state &st )
        {
            using res_type = result_type<IntT>;
            using ulittle = etool::details::byte_order_little<IntT>;

            if( st.size( ) >= sizeof(IntT) ) {
                IntT res = ulittle::read( st.get( ) );
                st.inc_shift(sizeof(IntT));
                return res_type::ok(res);
            }
            return res_type::fail("Not enough data");
        }

        static
        result_type<std::string> read_string( state &st, size_t string_len )
        {
            using res_type = result_type<std::string>;
            if( st.size( ) >= string_len ) {
                std::string res( st.get( ), st.get( ) + string_len );
                st.inc_shift( string_len );
                return res_type::ok(res);
            }
            return res_type::fail("Not enough data");
        }
    };
}

#endif // PARSER_H
