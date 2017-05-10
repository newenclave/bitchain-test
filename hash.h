#ifndef HASH_H
#define HASH_H

#include <cstdint>
#include <memory>
#include <memory.h>

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
            const std::uint8_t * data =
                    reinterpret_cast<const std::uint8_t *>(dat);
            digit_block dst;
            get( dst, data, len * sizeof(U) );
            return std::string(&dst[0], &dst[digit_length]);
        }

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

        template <typename U>
        static
        void append( const U *dat, size_t len, std::string &out )
        {
            auto old = out.size( );
            out.resize( old +  digit_length );
            get( &out[old], dat, len );
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

    };

    struct ripemd160 {
        static const size_t digit_length = RIPEMD160_DIGEST_LENGTH;
        using digit_block = std::uint8_t[digit_length];

        template <typename U>
        static
        std::string get_string( const U *dat, size_t len )
        {
            const std::uint8_t * data =
                    reinterpret_cast<const std::uint8_t *>(dat);
            digit_block dst;
            get( dst, data, len * sizeof(U) );
            return std::string(&dst[0], &dst[digit_length]);
        }

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

        template <typename U>
        static
        void append( const U *dat, size_t len, std::string &out )
        {
            auto old = out.size( );
            out.resize( old +  digit_length );
            get( &out[old], dat, len );
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
    };

    struct hash256 {

        static const size_t digit_length = sha256::digit_length;
        using digit_block                = sha256::digit_block;

        template <typename U>
        static
        void get( digit_block dst, const U *dat, size_t len )
        {
            sha256::get( dst, dat, len );
            sha256::get( dst, dst, digit_length );
        }

        template <typename U>
        static
        std::string get_string( const U *dat, size_t len )
        {
            digit_block dst;
            get( dst, dat, len );

            return std::string( &dst[0], &dst[digit_length] );
        }

        template <typename U>
        static
        void append( const U *dat, size_t len, std::string &out )
        {
            digit_block dst;
            get( dst, dat, len );
            out.append( &dst[0], &dst[digit_length] );
        }

    };

    struct hash160 {

        static const size_t digit_length = ripemd160::digit_length;
        using digit_block                = ripemd160::digit_block;

        template <typename U>
        static
        void get( digit_block dst, const U *dat, size_t len )
        {
            sha256::digit_block first_dst;

            sha256::get( first_dst, dat, len );
            ripemd160::get( dst, first_dst, sha256::digit_length );
        }

        template <typename U>
        static
        std::string get_string( const U *dat, size_t len )
        {
            digit_block second_dst;
            get(second_dst, dat, len);
            return std::string( &second_dst[0], &second_dst[digit_length] );
        }

        template <typename U>
        static
        void append( const U *dat, size_t len, std::string &out )
        {
            digit_block dst;
            get( dst, dat, len );
            out.append( &dst[0], &dst[digit_length] );
        }

    };

} }

#endif // HASH_H
