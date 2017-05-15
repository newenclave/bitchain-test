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

        enum { digest_length = DigitLen };
        using parent_type = ParentHash;
        using digest_block = std::uint8_t[digest_length];

        template <typename U>
        static
        std::string get_string( const U *dat, size_t len )
        {
            auto data = reinterpret_cast<const std::uint8_t *>(dat);
            digest_block dst;
            parent_type::get( dst, data, len * sizeof(U) );
            return std::string(&dst[0], &dst[digest_length]);
        }

        template <typename U>
        static
        void append( const U *dat, size_t len, std::string &out )
        {
            digest_block block;
            parent_type::get( block, dat, len );
            out.append( &block[0], &block[digest_length] );
        }

        template <typename U>
        static
        bool check( const U *dat, size_t len, const digest_block dst )
        {
            const std::uint8_t * data =
                    reinterpret_cast<const std::uint8_t *>(dat);
            digest_block tmp;
            get( tmp, data, len );
            return (memcmp( dst, tmp, digest_length ) == 0);
        }
    protected:
        common( ) = default;
    };

    struct sha256: public common<sha256, SHA256_DIGEST_LENGTH> {

        enum { digest_length = SHA256_DIGEST_LENGTH };
        using digest_block = std::uint8_t[digest_length];

        template <typename U>
        static
        void get( digest_block dst, const U *dat, size_t len )
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

        enum { digest_length = RIPEMD160_DIGEST_LENGTH };
        using digest_block = std::uint8_t[digest_length];

        template <typename U>
        static
        void get( digest_block dst, const U *dat, size_t len )
        {
            const std::uint8_t * data =
                    reinterpret_cast<const std::uint8_t *>(dat);
            RIPEMD160_CTX ctx;
            RIPEMD160_Init(&ctx);
            RIPEMD160_Update( &ctx, data, len * sizeof(U) );
            RIPEMD160_Final( dst, &ctx );
        }
    };

    struct hash256: public common<hash256, sha256::digest_length> {

        enum { digest_length = sha256::digest_length };
        using digest_block = sha256::digest_block;

        template <typename U>
        static
        void get( digest_block dst, const U *dat, size_t len )
        {
            sha256::get( dst, dat, len );
            sha256::get( dst, dst, digest_length );
        }
    };

    struct hash160: public common<hash160, ripemd160::digest_length> {

        enum { digest_length = ripemd160::digest_length };
        using digest_block   = ripemd160::digest_block;

        template <typename U>
        static
        void get( digest_block dst, const U *dat, size_t len )
        {
            sha256::digest_block first_dst;
            sha256::get( first_dst, dat, len );
            ripemd160::get( dst, first_dst, sha256::digest_length );
        }
    };

} }

#endif // HASH_H
