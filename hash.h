#ifndef HASH_H
#define HASH_H

#include <cstdint>
#include <memory>

#include "openssl/sha.h"
#include "openssl/ripemd.h"

namespace bchain { namespace hash {

    struct sha256 {
        static const size_t digit_length = SHA256_DIGEST_LENGTH;
        using digit_block = std::uint8_t[digit_length];

        template <typename U>
        static
        std::string get_string( const U *dat, size_t len )
        {
            auto data = reinterpret_cast<const std::uint8_t *>(dat);
            digit_block dst;
            get( dst, data, len );
            return std::string(&dst[0], &dst[digit_length]);
        }

        template <typename U>
        static
        void get( digit_block dst, const U *dat, size_t len )
        {
            auto data = reinterpret_cast<const std::uint8_t *>(dat);
            SHA256_CTX ctx;
            SHA256_Init(&ctx);
            SHA256_Update( &ctx, data, len );
            SHA256_Final( dst, &ctx );
        }

        template <typename U>
        static
        bool check( const U *dat, size_t len, const digit_block dst )
        {
            auto data = reinterpret_cast<const std::uint8_t *>(dat);
            digit_block tmp;
            get( tmp, data, len );
            return (memcmp( dst, tmp, digit_length ) == 0);
        }
    };

    struct ripemd160 {
        static const size_t digit_length = RIPEMD160_DIGEST_LENGTH;
        using digit_block = std::uint8_t[digit_length];

        template <typename U>
        static
        std::string get_string( const U *dat, size_t len )
        {
            auto data = reinterpret_cast<const std::uint8_t *>(dat);
            digit_block dst;
            get( dst, data, len );
            return std::string(&dst[0], &dst[digit_length]);
        }

        template <typename U>
        static
        void get( digit_block dst, const U *dat, size_t len )
        {
            auto data = reinterpret_cast<const std::uint8_t *>(dat);
            RIPEMD160_CTX ctx;
            RIPEMD160_Init(&ctx);
            RIPEMD160_Update( &ctx, data, len );
            RIPEMD160_Final( dst, &ctx );
        }

        template <typename U>
        static
        bool check( const U *dat, size_t len, const digit_block dst )
        {
            auto data = reinterpret_cast<const std::uint8_t *>(dat);
            digit_block tmp;
            get( tmp, data, len );
            return (memcmp( dst, tmp, digit_length ) == 0);
        }
    };

} }

#endif // HASH_H
