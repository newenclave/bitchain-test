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

static const char __ = -1;
static const char base58_code[ ]= "123456789"
                                  "ABCDEFGHJKLMNPQRSTUVWXYZ"
                                  "abcdefghijkmnopqrstuvwxyz";

static const int base58_index[0x100] = {
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,
    __, 0, 1, 2,  3, 4, 5, 6,  7, 8,__,__, __,__,__,__, // '0'-'9'
    __, 9,10,11, 12,13,14,15, 16,__,17,18, 19,20,21,__, // 'A'-'O'
    22,23,24,25, 26,27,28,29, 30,31,32,__, __,__,__,__, // 'P'-'Z'
    __,33,34,35, 36,37,38,39, 40,41,42,43, __,44,45,46, // 'a'-'o'
    47,48,49,50, 51,52,53,54, 55,56,57,__, __,__,__,__, // 'p'-'z'
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,
};

static std::uint8_t *copy_of_range( const std::uint8_t *src,
                                    size_t from, size_t to )
{
    std::uint8_t *dst = static_cast<std::uint8_t *>(malloc( (to - from) + 1));
    memcpy(dst, &src[from], to - from);
    dst[to - from] = '\0';
    return dst;
}

static std::uint8_t divmod58( std::uint8_t *number, size_t start, size_t len )
{
    std::uint32_t dig256;
    std::uint32_t tmp;
    std::uint32_t rem = 0;

    for( size_t i=start; i<len; i++ ) {

        dig256    = static_cast<std::uint32_t>( number[i] & 0xFF );
        tmp       = rem * 256 + dig256;
        number[i] = static_cast<std::uint8_t>( tmp / 58 );
        rem       = tmp % 58;

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

size_t base58_encoded_size( size_t len )
{
    return ((len+4)/5)*7;
}

size_t base58_decoded_size( size_t len )
{
    return (len/4)*3;
}

void base58_encode( std::uint8_t *dst, const std::uint8_t *src, size_t len )
{

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
            tmp[--j] = base58_code[mod];
        }

        while( (j < tlen) && (tmp[j] == base58_code[0]) ) {
            ++j;
        }

        while( --zc >= 0 ) {
            tmp[--j] = base58_code[0];
        }

        free(copy);
        memcpy( dst, &tmp[j], tlen - j);
        dst[tlen-j] = '\0';
    }
}

int base58_decode( std::uint8_t *dst, const std::uint8_t *src )
{
    size_t len = strlen((const char*)src);

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
                digit58 = base58_index[c];
            }

            if( digit58 < 0 ) {
                //fprintf(stderr,"Illegal character '%c' at %d.\n",(char)c,i);
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

        dst[len-(j-zc)] = '\0';
        return len-(j-zc);
    }
    return 0;
}

int main( )
{
    std::string data = "11111111111111111111";
    std::string t( base58_encoded_size( data.size( ) ), '\0' );
    base58_encode( (uint8_t *)&t[0],
            (const uint8_t *)data.c_str( ), data.size( ) );

    std::cout << t << "\n";

    data = std::string(data.size( ), 0);
    base58_decode((uint8_t *)&data[0], (const uint8_t *)t.c_str( ) );

    std::cout << data << "\n";

    return 0;
}

