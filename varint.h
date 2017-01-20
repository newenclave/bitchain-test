#ifndef VARINT_H
#define VARINT_H

#include "byte_order.h"

namespace bchain {

    template <bool Swap>
    struct varint {

        typedef std::uint64_t value_type;
        static const bool swap = Swap;

        enum varint_type {
            VI16 = 0xFD,
            VI32 = 0xFE,
            VI64 = 0xFF,
        };

        static value_type value( value_type v )
        {
            return byte_order<std::uint64_t, Swap>::value( v );
        }

        template <typename U>
        static size_t write( std::uint64_t v, U *out )
        {
            std::uint8_t *o = reinterpret_cast<std::uint8_t *>(out);
            if( v < VI16 ) {
                *o = v & 0xFF;
                return 1;
            } else {
                if( v <= UINT16_MAX ) {
                    *o = VI16;
                    return byte_order<std::uint16_t, Swap>::write(v, o + 1) + 1;
                } else if( v <= UINT32_MAX ) {
                    *o = VI32;
                    return byte_order<std::uint32_t, Swap>::write(v, o + 1) + 1;
                } else {
                    *o = VI64;
                    return byte_order<std::uint64_t, Swap>::write(v, o + 1) + 1;
                }
            }
        }

        template <typename U>
        static value_type read( const U *in, size_t *len = nullptr )
        {
            const std::uint8_t *o = reinterpret_cast<const std::uint8_t *>(in);
            if( *o < VI16 ) {
                if( len ) {
                    *len = 1;
                }
                return *o;
            } else {
                switch (*o) {
                case VI16:
                    if( len ) {
                        *len = sizeof(std::uint16_t) + 1;
                    }
                    return byte_order<std::uint16_t, Swap>::read( o + 1 );
                case VI32:
                    if( len ) {
                        *len = sizeof(std::uint32_t) + 1;
                    }
                    return byte_order<std::uint32_t, Swap>::read( o + 1 );
                case VI64:
                    if( len ) {
                        *len = sizeof(std::uint64_t) + 1;
                    }
                    return byte_order<std::uint64_t, Swap>::read( o + 1 );

                default: /// must not be here; just for avoiding warnings
                    if( len ) {
                        *len = 0;
                    }
                    return value_type(0);
                }
            }
        }
    };
}

#endif // VARINT_H
