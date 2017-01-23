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
#include "base58.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>

#include <memory.h>

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
    std::cout << base58::decode(base58::encode( "Hello!" ));
    return 0;
}


//#include <stdint.h>
//#include <stdlib.h>


//static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
//                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
//                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
//                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
//                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
//                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
//                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
//                                '4', '5', '6', '7', '8', '9', '+', '/'};
//static char *decoding_table = NULL;
//static int mod_table[] = {0, 2, 1};


//char *base64_encode(const unsigned char *data,
//                    size_t input_length,
//                    size_t *output_length) {

//    *output_length = 4 * ((input_length + 2) / 3);

//    char *encoded_data = malloc(*output_length);
//    if (encoded_data == NULL) return NULL;

//    for (int i = 0, j = 0; i < input_length;) {

//        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
//        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
//        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

//        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

//        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
//        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
//        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
//        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
//    }

//    for (int i = 0; i < mod_table[input_length % 3]; i++)
//        encoded_data[*output_length - 1 - i] = '=';

//    return encoded_data;
//}


//unsigned char *base64_decode(const char *data,
//                             size_t input_length,
//                             size_t *output_length) {

//    if (decoding_table == NULL) build_decoding_table();

//    if (input_length % 4 != 0) return NULL;

//    *output_length = input_length / 4 * 3;
//    if (data[input_length - 1] == '=') (*output_length)--;
//    if (data[input_length - 2] == '=') (*output_length)--;

//    unsigned char *decoded_data = malloc(*output_length);
//    if (decoded_data == NULL) return NULL;

//    for (int i = 0, j = 0; i < input_length;) {

//        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
//        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
//        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
//        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

//        uint32_t triple = (sextet_a << 3 * 6)
//        + (sextet_b << 2 * 6)
//        + (sextet_c << 1 * 6)
//        + (sextet_d << 0 * 6);

//        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
//        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
//        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
//    }

//    return decoded_data;
//}


//void build_decoding_table() {

//    decoding_table = malloc(256);

//    for (int i = 0; i < 64; i++)
//        decoding_table[(unsigned char) encoding_table[i]] = i;
//}


//void base64_cleanup() {
//    free(decoding_table);
//}
