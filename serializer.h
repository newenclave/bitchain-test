#ifndef SERIALIZER_H
#define SERIALIZER_H

#include <algorithm>

#include "hash.h"
#include "base58.h"

#include "etool/details/byte_order.h"

namespace bchain {

    struct serializer {

        using endian = etool::details::endian;

        static
        void append_string( std::string &out, const std::string &val )
        {
            out.append( val );
        }

        static
        void append_string( std::string &out,
                            const std::string &val,
                            size_t max_size )
        {
            if( val.size( ) < max_size ) {
                std::string tmp(val);
                tmp.append( std::string(max_size - val.size( ), '\0') );
                out.append(tmp);
            } else {
                out.append( val.begin( ), val.begin( ) + max_size );
            }
        }

        template <typename IntT>
        static
        void append_uint( std::string &out, IntT data )
        {
            auto old = out.size( );
            out.resize( old + sizeof(data) );
            etool::details::byte_order<IntT, endian::LITTLE>
                          ::write(data, &out[old]);
        }
    };

}

#endif // SERIALIZER_H
