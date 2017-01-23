#ifndef BASE58_H
#define BASE58_H

#include <string>
#include <cstdint>
#include <memory.h>

#include "hash.h"

namespace bchain {

    struct base58 {

        static size_t encoded_size( size_t len )
        {
            return ( (len + 4) / 5 ) * 7;
        }

        static size_t decoded_size( size_t len )
        {
            return ( len / 4 ) * 3;
        }

        static std::string encode( const std::string &src )
        {
            std::string tmp(encoded_size( src.size( ) ), 0);
            size_t len = encode( reinterpret_cast<std::uint8_t *>(&tmp[0]),
                           reinterpret_cast<const std::uint8_t *>(src.c_str( )),
                    src.size( ) );
            tmp.resize( len );
            return tmp;
        }

        static std::string decode( const std::string &src )
        {
            std::string tmp(decoded_size( src.size( ) ), 0);
            int len = decode( reinterpret_cast<std::uint8_t *>(&tmp[0]),
                        reinterpret_cast<const std::uint8_t *>(src.c_str( )),
                    src.size( ) );
            if( len > 0 ) {
                tmp.resize( len );
            } else {
                tmp.clear( );
            }
            return tmp;
        }

        template <typename U>
        static
        int decode( std::uint8_t *dst, const U *sources, size_t len )
        {
            const std::uint8_t * src =
                    reinterpret_cast<const std::uint8_t *>(sources);
            *dst = '\0';

            if( len > 0 ) {

                size_t j = len;
                size_t c;
                int    digit58;
                size_t zc = 0;
                size_t start;
                size_t mod;

                std::uint8_t input58[len];
                std::uint8_t tmp[len];

                for( size_t i=0; i < len; ++i ) {

                    c = src[i];

                    digit58 = -1;

                    if( c < 128) {
                        digit58 = index(c);
                    }

                    if( digit58 < 0 ) {
                        return -1;
                    }

                    input58[i] = static_cast<std::uint8_t>(digit58 & 0xFF);
                }

                while( zc<len && input58[zc] == 0 ) {
                    ++zc;
                }

                start = zc;

                while( start < len ) {

                    mod = divmod256(input58, start, len);

                    if(input58[start]==0) {
                        ++start;
                    }
                    tmp[--j] = mod;
                }

                while(j<len && tmp[j]==0) ++j;

                memcpy( dst, &tmp[j-zc], len-(j-zc) );

                dst[ len - (j-zc) ] = '\0';
                return len-(j-zc);
            }
            return 0;
        }

        template <typename U>
        static
        size_t encode( std::uint8_t *dst, const U *sources, size_t len )
        {
            const std::uint8_t * src =
                    reinterpret_cast<const std::uint8_t *>(sources);
            *dst = '\0';
            if( len > 0 ) {

                size_t tlen     = len * 2;
                size_t j        = tlen;
                int zc          = 0;
                size_t start    = 0;
                size_t mod      = 0;

                std::uint8_t *copy = copy_of_range( src, 0, len );
                std::uint8_t tmp[tlen];

                while((size_t)zc<len && copy[zc]=='\0') ++zc;

                start = zc;
                while( start < len ) {

                    mod = divmod58( copy, start, len );
                    if( copy[start] == 0 ) {
                        ++start;
                    }
                    tmp[--j] = code(mod);
                }

                while( (j < tlen) && (tmp[j] == code(0)) ) {
                    ++j;
                }

                while( --zc >= 0 ) {
                    tmp[--j] = code( 0 );
                }

                free(copy);
                memcpy( dst, &tmp[j], tlen - j);
                dst[tlen-j] = '\0';
                return tlen - j;
            }
            return 0;
        }

        template <typename U>
        static
        std::string encode_check( const U *sources, size_t len )
        {
            std::string res(encoded_size( len ) + 4, 0);
            size_t res_len =
                    encode_check( reinterpret_cast<std::uint8_t *>(&res[0]),
                                  sources, len );
            res.resize( res_len );
            return res;
        }


        template <typename U>
        static
        size_t encode_check( std::uint8_t *dst, const U *sources, size_t len )
        {
            const std::uint8_t * src =
                    reinterpret_cast<const std::uint8_t *>(sources);

            std::string tmp;
            tmp.reserve( len + 4 );
            tmp.assign( src, src + len );

            tmp.resize( tmp.size( ) + 4 );

            std::uint8_t digit[hash::sha256::digit_length];
            hash::sha256::get( digit, sources, len );

            tmp[len + 0] = digit[0];
            tmp[len + 1] = digit[1];
            tmp[len + 2] = digit[2];
            tmp[len + 3] = digit[3];

            size_t res_len = encode( dst, tmp.c_str( ), tmp.size( ) );
            return res_len;
        }


    private:

        static std::uint8_t *copy_of_range( const std::uint8_t *src,
                                            size_t from, size_t to )
        {
            std::uint8_t *dst =
                    static_cast<std::uint8_t *>(malloc( (to - from) + 1));
            memcpy(dst, &src[from], to - from);
            dst[to - from] = '\0';
            return dst;
        }

        static char index( size_t id )
        {
            static const char XX = -1;
            static const char table[0x100] = {
                XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
                XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
                XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
                XX, 0, 1, 2,  3, 4, 5, 6,  7, 8,XX,XX, XX,XX,XX,XX, // '0'-'9'
                XX, 9,10,11, 12,13,14,15, 16,XX,17,18, 19,20,21,XX, // 'A'-'O'
                22,23,24,25, 26,27,28,29, 30,31,32,XX, XX,XX,XX,XX, // 'P'-'Z'
                XX,33,34,35, 36,37,38,39, 40,41,42,43, XX,44,45,46, // 'a'-'o'
                47,48,49,50, 51,52,53,54, 55,56,57,XX, XX,XX,XX,XX, // 'p'-'z'
                XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
                XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
                XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
                XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
                XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
                XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
                XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
                XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
            };
            return table[id % 0x100];
        }

        static char code( size_t id )
        {
            static const char table[ ]= "123456789"
                                        "ABCDEFGHJKLMNPQRSTUVWXYZ"
                                        "abcdefghijkmnopqrstuvwxyz";
            return table[id % 58];
        }

        static std::uint8_t divmod58( std::uint8_t *number256,
                                      size_t start, size_t len )
        {
            std::uint32_t dig256;
            std::uint32_t tmp;
            std::uint32_t rem = 0;

            for( size_t i = start; i<len; i++ ) {
                dig256       = static_cast<std::uint32_t>( number256[i] & 0xFF );
                tmp          = rem * 256 + dig256;
                number256[i] = static_cast<std::uint8_t>( tmp / 58 );
                rem          = tmp % 58;
            }

            return static_cast<std::uint8_t>(rem & 0xFF);
        }

        static std::uint8_t divmod256( std::uint8_t *number58,
                                       size_t start, size_t len )
        {
            std::uint32_t dig58;
            std::uint32_t tmp;
            std::uint32_t rem = 0;

            for(size_t i=start; i < len; i++) {
                dig58       = static_cast<uint32_t>( number58[i] & 0xFF );
                tmp         = rem * 58 + dig58;
                number58[i] = static_cast<std::uint8_t>( tmp / 256 );
                rem         = tmp % 256;
            }
            return static_cast<std::uint8_t>(rem);
        }
    };
}

#endif // BASE58_H
