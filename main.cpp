#include <iostream>
#include <string>
#include <climits>
#include <sys/types.h>
#include <arpa/inet.h>

#include <functional>
#include <memory>

#include "openssl/sha.h"
#include "openssl/ripemd.h"

#include "byte_order.h"
#include "varint.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>

using namespace bchain;

struct endian
{
private:

    template <typename T>
    struct val{

        typedef T      (* convert_type)(T);
        typedef size_t (* write_type)(T, std::uint8_t *);
        typedef T      (* read_type)(const std::uint8_t *, size_t *);

        convert_type  value;
        write_type    write;
        read_type     read;
    };

    template <bool Val>
    void set( )
    {
        typedef byte_order<std::uint8_t,  Val> bytes8;
        typedef byte_order<std::uint16_t, Val> bytes16;
        typedef byte_order<std::uint32_t, Val> bytes32;
        typedef byte_order<std::uint64_t, Val> bytes64;
        typedef varint<Val>                    bytesv;

        v8.value  = &bytes8::value;
        v8.write  = &bytes8::template write<std::uint8_t>;
        v8.read   = &bytes8::template read<std::uint8_t>;

        v16.value  = &bytes16::value;
        v16.write  = &bytes16::template write<std::uint8_t>;
        v16.read   = &bytes16::template read<std::uint8_t>;

        v32.value  = &bytes32::value;
        v32.write  = &bytes32::template write<std::uint8_t>;
        v32.read   = &bytes32::template read<std::uint8_t>;

        v64.value  = &bytes64::value;
        v64.write  = &bytes64::template write<std::uint8_t>;
        v64.read   = &bytes64::template read<std::uint8_t>;

        var.value = &bytesv::value;
        var.write = &bytesv::template write<std::uint8_t>;
        var.read  = &bytesv::template read<std::uint8_t>;
    }

public:

    endian( bool bigendian )
    {
        if( bigendian ) {
            if( host_byte_order::is_big_endian( ) ) {
                set<false>( );
            } else {
                set<true>( );
            }
        } else {
            if( host_byte_order::is_big_endian( ) ) {
                set<true>( );
            } else {
                set<false>( );
            }
        }
    }

    val<std::uint8_t>  v8;
    val<std::uint16_t> v16;
    val<std::uint32_t> v32;
    val<std::uint64_t> v64;
    val<std::uint64_t> var;

};

struct big_endian: public endian {
    big_endian( )
        :endian(true)
    { }
};

struct little_endian: public endian {
    little_endian( )
        :endian(false)
    { }
};

std::ostream &bintohex( std::ostream &o, const std::string &data )
{
    o << std::hex;
    for( auto a: data ) {
        o << (std::uint16_t)(std::uint8_t)(a);
    }
    return o;
}

void sha256_digit( std::uint8_t *out, char *message, size_t len )
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update( &ctx, message, len );
    SHA256_Final( out, &ctx );
}

void ripemd169_digit( std::uint8_t *out, char *message, size_t len )
{
    RIPEMD160_CTX ctx;
    RIPEMD160_Init(&ctx);
    RIPEMD160_Update( &ctx, message, len );
    RIPEMD160_Final( out, &ctx );
}

class bn_ctx {

    BN_CTX *ctx_ = nullptr;

public:

    bn_ctx( )
        :ctx_(BN_CTX_new( ))
    {
        if( ctx_ ) {
            BN_CTX_start(ctx_);
        }
    }

    ~bn_ctx( )
    {
        if( ctx_ ) {
            BN_CTX_end(ctx_);
            BN_CTX_free(ctx_);
        }
    }

    BN_CTX *get( )
    {
        return ctx_;
    }
};

EC_KEY *bbp_ec_new_keypair(const uint8_t *priv_bytes) {

    EC_KEY *key;
    BIGNUM *priv;
    bn_ctx  ctx;
    const EC_GROUP *group;
    EC_POINT *pub;

    /* init empty OpenSSL EC keypair */

    key = EC_KEY_new_by_curve_name(NID_secp256k1);

    /* set private key through BIGNUM */

    priv = BN_new();
    BN_bin2bn(priv_bytes, 32, priv);
    EC_KEY_set_private_key(key, priv);

    /* derive public key from private key and group */

    group = EC_KEY_get0_group(key);
    pub = EC_POINT_new(group);
    EC_POINT_mul(group, pub, priv, NULL, NULL, ctx.get( ));
    EC_KEY_set_public_key(key, pub);

    /* release resources */

    EC_POINT_free(pub);
    BN_clear_free(priv);

    return key;
}

int main( )
{
    return 0;
}

