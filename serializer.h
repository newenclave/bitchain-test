#ifndef SERIALIZER_H
#define SERIALIZER_H

#include <algorithm>

#include "hash.h"
#include "base58.h"

#include "etool/details/byte_order.h"
#include "varint.h"

namespace bchain {

    struct serializer {

        using endian = etool::details::endian;

        static
        void append_string( const std::string &val, std::string &out )
        {
            out.append( val );
        }

        static
        void append_string( const std::string &val,
                            size_t max_size,
                            std::string &out )
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
        void append_uint( IntT data, std::string &out )
        {
            auto old = out.size( );
            out.resize( old + sizeof(data) );
            etool::details::byte_order<IntT, endian::LITTLE>
                          ::write(data, &out[old] );
        }

        template <typename IntT>
        static
        void append_varint( IntT data, std::string &out )
        {
            auto old = out.size( );
            out.resize( old + varint::result_length(data) );
            varint::write( data, &out[old] );
        }


    };

}

#endif // SERIALIZER_H
