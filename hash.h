#ifndef HASH_H
#define HASH_H

#include <cstdint>
#include <memory>
#include <memory.h>

#include "openssl/sha.h"
#include "openssl/ripemd.h"

namespace bchain { namespace hash {

    template <typename ParentHash, size_t DigitLen>
    struct common {

        enum { digit_length = DigitLen };
        using parent_type = ParentHash;
        using digit_block = std::uint8_t[digit_length];

        template <typename U>
        static
        std::string get_string( const U *dat, size_t len )
        {
            auto data = reinterpret_cast<const std::uint8_t *>(dat);
            digit_block dst;
            parent_type::get( dst, data, len * sizeof(U) );
            return std::string(&dst[0], &dst[digit_length]);
        }

        template <typename U>
        static
        void append( const U *dat, size_t len, std::string &out )
        {
            digit_block block;
            parent_type::get( block, dat, len );
            out.append( &block[0], &block[digit_length] );
        }

        template <typename U>
        static
        bool check( const U *dat, size_t len, const digit_block dst )
        {
            const std::uint8_t * data =
                    reinterpret_cast<const std::uint8_t *>(dat);
            digit_block tmp;
            get( tmp, data, len );
            return (memcmp( dst, tmp, digit_length ) == 0);
        }
    protected:
        common( ) = default;
    };

    struct sha256: public common<sha256, SHA256_DIGEST_LENGTH> {

        enum { digit_length = SHA256_DIGEST_LENGTH };
        using digit_block = std::uint8_t[digit_length];

        template <typename U>
        static
        void get( digit_block dst, const U *dat, size_t len )
        {
            const std::uint8_t * data =
                    reinterpret_cast<const std::uint8_t *>(dat);
            SHA256_CTX ctx;
            SHA256_Init(&ctx);
            SHA256_Update( &ctx, data, len * sizeof(U) );
            SHA256_Final( dst, &ctx );
        }

    };

    struct ripemd160: public common<ripemd160, RIPEMD160_DIGEST_LENGTH> {

        enum { digit_length = RIPEMD160_DIGEST_LENGTH };
        using digit_block = std::uint8_t[digit_length];

        template <typename U>
        static
        void get( digit_block dst, const U *dat, size_t len )
        {
            const std::uint8_t * data =
                    reinterpret_cast<const std::uint8_t *>(dat);
            RIPEMD160_CTX ctx;
            RIPEMD160_Init(&ctx);
            RIPEMD160_Update( &ctx, data, len * sizeof(U) );
            RIPEMD160_Final( dst, &ctx );
        }
    };

    struct hash256: public common<hash256, sha256::digit_length> {

        enum { digit_length = sha256::digit_length };
        using digit_block = sha256::digit_block;

        template <typename U>
        static
        void get( digit_block dst, const U *dat, size_t len )
        {
            sha256::get( dst, dat, len );
            sha256::get( dst, dst, digit_length );
        }
    };

    struct hash160: public common<hash160, ripemd160::digit_length> {

        enum { digit_length = ripemd160::digit_length };
        using digit_block   = ripemd160::digit_block;

        template <typename U>
        static
        void get( digit_block dst, const U *dat, size_t len )
        {
            sha256::digit_block first_dst;
            sha256::get( first_dst, dat, len );
            ripemd160::get( dst, first_dst, sha256::digit_length );
        }
    };

} }

#endif // HASH_H
