#ifndef CRYPTO_H
#define CRYPTO_H

#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/obj_mac.h"
#include "openssl/ecdsa.h"
#include "openssl/opensslv.h"
#include "openssl/ssl.h"

#include <memory>
#include <random>

namespace bchain { namespace crypto {

#define BITCHAIN_CRYPTO_COMMON_IMPL( ThisType, ValueType  ) \
                                                            \
    ThisType( ThisType &o ) = delete;                       \
    ThisType &operator = ( ThisType &o ) = delete;          \
                                                            \
    ThisType( ThisType &&o )                                \
        :val_(o.release( ))                                 \
    { }                                                     \
                                                            \
    ThisType &operator = ( ThisType &&o )                   \
    {                                                       \
        val_ = o.release( );                                \
        return *this;                                       \
    }                                                       \
                                                            \
    ValueType *get( )                                       \
    {                                                       \
        return val_;                                        \
    }                                                       \
                                                            \
    const ValueType *get( ) const                           \
    {                                                       \
        return val_;                                        \
    }                                                       \
                                                            \
    ValueType *release( )                                   \
    {                                                       \
        ValueType *tmp = val_;                              \
        val_ = nullptr;                                     \
        return tmp;                                         \
    }                                                       \
                                                            \
    void swap( ThisType &other )                            \
    {                                                       \
        std::swap( val_, other.val_ );                      \
    }                                                       \
                                                            \
    operator bool ( ) const                                 \
    {                                                       \
        return get( ) != nullptr;                           \
    }                                                       \
                                                            \
    private:                                                \
                                                            \
        ValueType *val_ = nullptr

    class bn_ctx {

    public:
        using value_type = BN_CTX;
        using this_type  = bn_ctx;

        bn_ctx( )
            :val_(BN_CTX_new( ))
        {
            if( val_ ) {
                BN_CTX_start( val_ );
            }
        }

        ~bn_ctx( )
        {
            if( val_ ) {
                BN_CTX_end( val_ );
                BN_CTX_free( val_ );
            }
        }

        BITCHAIN_CRYPTO_COMMON_IMPL(bn_ctx, BN_CTX);

    };

    class bignum {

    public:
        using value_type = BIGNUM;
        using this_type  = bignum;

        bignum( )
            :val_(BN_new( ))
        { }

        ~bignum( )
        {
            if(val_) {
                BN_free( val_ );
            }
        }

        BITCHAIN_CRYPTO_COMMON_IMPL(bignum, BIGNUM);
    };

    class ec_point {
    public:
        using value_type = EC_POINT;
        using this_type  = ec_point;

        ec_point( EC_POINT *point )
            :val_(point)
        { }

        ec_point( const EC_GROUP *group )
            :val_(EC_POINT_new(group))
        { }

        ~ec_point( )
        {
            if( val_ ) {
                EC_POINT_free( val_ );
            }
        }

        BITCHAIN_CRYPTO_COMMON_IMPL(ec_point, EC_POINT);
    };

    class key {

    public:
        using value_type = EC_KEY;
        using this_type  = key;

        key( EC_KEY *k )
            :val_(k)
        { }

        key( )
        { }

        ~key( )
        {
            if( val_ ) {
                EC_KEY_free( val_ );
            }
        }
        BITCHAIN_CRYPTO_COMMON_IMPL(key, EC_KEY);
    };

    class signature {
    public:

        signature( )
        { }

        signature( ECDSA_SIG *s )
            :val_(s)
        { }

        ~signature( )
        {
            if( val_ ) {
                ECDSA_SIG_free( val_ );
            }
        }

        static
        size_t sign_size( EC_KEY *k )
        {
            if(k) {
                return ECDSA_size(k);
            } else {
                return 0;
            }
        }

        template <typename U>
        static
        signature sign( const U  *mess, size_t len, EC_KEY *k )
        {
            const unsigned char *data =
                    reinterpret_cast<const unsigned char *>(mess);

            signature s( ECDSA_do_sign(data, len * sizeof(U), k) );

            return s;
        }

        template <typename U>
        int check( const U  *mess, size_t len, EC_KEY *k )
        {
            const unsigned char *data =
                    reinterpret_cast<const unsigned char *>(mess);

            return ECDSA_do_verify( data, len * sizeof(U), val_, k );
        }

        template <typename U>
        static
        int check( const U  *mess, size_t len, ECDSA_SIG *sig, EC_KEY *k )
        {
            const unsigned char *data =
                    reinterpret_cast<const unsigned char *>(mess);

            return ECDSA_do_verify( data, len * sizeof(U), sig, k );
        }

        BITCHAIN_CRYPTO_COMMON_IMPL(signature, ECDSA_SIG);
    };

#undef BITCHAIN_CRYPTO_COMMON_IMPL

    struct key_pair {

        static const size_t private_bytes_length = 32;
        using private_bytes_block = std::uint8_t[private_bytes_length];

        template <typename U>
        static
        key create_private( const U* priv_bytes, size_t len )
        {
            key res;
            key k(EC_KEY_new_by_curve_name(NID_secp256k1));
            if( k ) {
                bignum  priv;
                if( !priv ) {
                    return res;
                }

                const std::uint8_t *pb =
                        reinterpret_cast<const std::uint8_t *>(priv_bytes);

                BN_bin2bn( pb, len, priv.get( ) );
                if(1 != EC_KEY_set_private_key( k.get( ), priv.get( ) ) ) {
                    return res;
                }

                const EC_GROUP *group = EC_KEY_get0_group(k.get( ));
                ec_point pub(group);
                bn_ctx   ctx;

                if( !pub || !ctx || !group ) {
                    return res;
                }

                if( 1 != EC_POINT_mul( group, pub.get( ), priv.get( ),
                                       NULL, NULL, ctx.get( ) ) )
                {
                    return res;
                }

                if( 1 != EC_KEY_set_public_key(k.get( ), pub.get( ) ) ) {
                    return res;
                }

                res.swap( k );
            }
            return res;
        }

        template <typename U>
        static
        key create_public( const U* pub_bytes, size_t len )
        {
            key res;
            key k(EC_KEY_new_by_curve_name(NID_secp256k1));

            if( k ) {
                const std::uint8_t *pbc =
                        reinterpret_cast<const std::uint8_t *>(pub_bytes);

                EC_KEY *kk = k.get( );
                o2i_ECPublicKey( &kk, &pbc, len );
                res.swap( k );
            }

            return res;
        }

    };
}}

#endif // CRYPTO_H
