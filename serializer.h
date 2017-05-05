#ifndef SERIALIZER_H
#define SERIALIZER_H

#include <algorithm>

#include "byte_order.h"
#include "hash.h"
#include "base58.h"

namespace bchain {

    struct serializer {

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
            size_t min_val = std::min( val.size( ), max_size );
            out.append( val.begin( ), val.begin( ) + min_val );
            out.append( std::string( ) );
        }

    };

}

#endif // SERIALIZER_H
