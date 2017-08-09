
#include <deque>
#include <cstdint>
#include <string>
#include <iostream>

#include "etool/details/byte_order.h"
#include "etool/details/byte_hex.h"

#include "etool/dumper/dump.h"
#include "etool/slices/memory.h"

#include "crypto.h"

#include "hash.h"
#include "tx.h"

namespace {

    //return main_script0( );
    uint8_t priv_bytes[32] = {
        0x16, 0x26, 0x07, 0x83, 0xe4, 0x0b, 0x16, 0x73,
        0x16, 0x73, 0x62, 0x2a, 0xc8, 0xa5, 0xb0, 0x45,
        0xfc, 0x3e, 0xa4, 0xaf, 0x70, 0xf7, 0x27, 0xf3,
        0xf9, 0xe9, 0x2b, 0xdd, 0x3a, 0x1d, 0xdc, 0x42
    };

    uint8_t pub_bytes[33] = {
        0x02,
        0x82, 0x00, 0x6e, 0x93, 0x98, 0xa6, 0x98, 0x6e,
        0xda, 0x61, 0xfe, 0x91, 0x67, 0x4c, 0x3a, 0x10,
        0x8c, 0x39, 0x94, 0x75, 0xbf, 0x1e, 0x73, 0x8f,
        0x19, 0xdf, 0xc2, 0xdb, 0x11, 0xdb, 0x1d, 0x28
    };

    namespace op {
        enum class code: std::uint8_t {
            OP_0            =  0,
            OP_FALSE        =  0,
            OP_PUSHDATA0    =  0x4b,
            OP_PUSHDATA1    =  0x4c,
            OP_PUSHDATA2    =  0x4d,
            OP_PUSHDATA4    =  0x4e,
            OP_1            =  1 + 0x50,
            OP_2            =  2 + 0x50,
            OP_3            =  3 + 0x50,
            OP_4            =  4 + 0x50,
            OP_5            =  5 + 0x50,
            OP_6            =  6 + 0x50,
            OP_7            =  7 + 0x50,
            OP_8            =  8 + 0x50,
            OP_9            =  9 + 0x50,
            OP_10           = 10 + 0x50,
            OP_11           = 11 + 0x50,
            OP_12           = 12 + 0x50,
            OP_13           = 13 + 0x50,
            OP_14           = 14 + 0x50,
            OP_15           = 15 + 0x50,
            OP_16           = 16 + 0x50,
            OP_TRUE         = OP_1,
            OP_DUP          = 0x76,
            OP_EQUAL        = 0x87,
            OP_EQUALVERIFY  = 0x88,
            OP_ADD          = 0x93,
            OP_SUB          = 0x94,
            OP_HASH160      = 0xa9,
            OP_CHECKSIG     = 0xac,
            OP_HASH256      = 0xaa,
        };

        inline
        std::uint8_t to_byte( code c )
        {
            return static_cast<std::uint8_t>(c);
        }

        inline
        char to_char( code c )
        {
            return static_cast<char>(c);
        }

        inline
        code to_code( std::uint8_t c )
        {
            return static_cast<code>(c);
        }
    }

    struct standarts {

        static
        std::string len_header1( std::size_t val )
        {
            static const auto var_size =
                    static_cast<std::size_t>(op::code::OP_PUSHDATA0);
            std::string res;
            if( val > var_size ) {
                res.push_back( op::to_char(op::code::OP_PUSHDATA1) );
            }
            res.push_back( static_cast<char>( val ) );

            return res;
        }

        static
        std::string len_header2( std::size_t val )
        {
            using bo = etool::details::byte_order_little<std::uint16_t>;
            char out[2];
            bo::write( static_cast<std::uint16_t>(val & 0xFFFF), out );
            std::string res;
            res.push_back( op::to_char(op::code::OP_PUSHDATA2) );
            res.push_back(out[0]);
            res.push_back(out[1]);

            return res;
        }

        static
        std::string len_header4( std::size_t val )
        {
            using bo = etool::details::byte_order_little<std::uint32_t>;
            char out[4];

            bo::write( static_cast<std::uint32_t>(val & 0xFFFFFFFF), out );
            std::string res;

            res.push_back( op::to_char(op::code::OP_PUSHDATA4) );
            res.push_back(out[0]);
            res.push_back(out[1]);
            res.push_back(out[2]);
            res.push_back(out[3]);

            return res;
        }

        static
        std::string len_header( std::size_t val)
        {
            if( val <= 0xFF ) {
                return len_header1( val );
            } else if( val <= 0xFFFF ) {
                return len_header2( val );
            } else {
                return len_header4( val );
            }
        }

        static
        std::string P2PKH_out( const std::string &public_hash160 )
        {
            std::string res;
            res.push_back( op::to_char( op::code::OP_DUP         ) );
            res.push_back( op::to_char( op::code::OP_HASH160     ) );

            res.push_back( static_cast<char>(public_hash160.size( ) &0xFF ) );
            res.append( public_hash160.begin( ), public_hash160.end( ) );

            res.push_back( op::to_char( op::code::OP_EQUALVERIFY ) );
            res.push_back( op::to_char( op::code::OP_CHECKSIG    ) );
            return res;
        }

        template <typename PT>
        static
        std::string P2PKH_in( const std::string &sign, const PT &pub )
        {
            using hash160 = bchain::hash::hash160;

            std::string res;

            res.append( len_header( sign.size( ) + 1 ) );
            res.append( sign.begin( ), sign.end( ) );
            res.push_back( 0x01 );

            res.append( len_header( pub.size( ) ) );
            res.append( pub.begin( ), pub.end( ) );

            auto h = hash160::get_string( pub.data( ), pub.size( ) );
            res.append( P2PKH_out( h ) );

            return res;
        }

    };

    class stack {
    public:
        using byte = std::uint8_t;
        using container_type = std::deque<byte>;

        void push( byte val )
        {
            state_.push_front( val );
        }

        void push_data1( const std::string &data )
        {
            static const auto var_size =
                    static_cast<std::size_t>(op::code::OP_PUSHDATA0);
            state_.insert( state_.begin(  ), data.begin( ), data.end( ) );
            push( static_cast<byte>(data.size( ) ) );
            if( data.size( ) > var_size ) {
                push( op::to_byte(op::code::OP_PUSHDATA1) );
            }
        }

        void push_data2( const std::string &data )
        {
            using bo = etool::details::byte_order_little<std::uint16_t>;
            byte val[2];
            bo::write( static_cast<std::uint16_t>(data.size( ) & 0xFFFF), val );
            state_.insert( state_.begin( ), data.begin( ), data.end( ) );
            push(val[1]);
            push(val[0]);
            push( op::to_byte(op::code::OP_PUSHDATA2) );
        }

        void push_data4( const std::string &data )
        {
            using bo = etool::details::byte_order_little<std::uint32_t>;
            byte val[4];
            bo::write( static_cast<std::uint32_t>(data.size( ) & 0xFFFFFFFF),
                       val );
            state_.insert( state_.begin( ), data.begin( ), data.end( ) );
            push(val[3]);
            push(val[2]);
            push(val[1]);
            push(val[0]);
            push( op::to_byte(op::code::OP_PUSHDATA4) );
        }

        void pop(  )
        {
            state_.pop_front( );
        }

        const container_type &container( ) const
        {
            return state_;
        }

        container_type &container( )
        {
            return state_;
        }

    private:
        container_type state_;
    };

}

using namespace bchain;
using namespace etool;

//76
//A9
//    14
//    6B F1 9E 55 F9 4D 98 6B
//    46 40 C1 54 D8 64 69 93
//    41 91 95 11
//88
//AC

std::string operator "" _bin( const char *val, size_t len )
{
    auto res = details::byte_hex::from_hex( val, len );
    if( res ) {
        return std::move(*res);
    }
    return "<FAILED>";
}

std::ostream &printhex( std::ostream &out, const std::string &str )
{
    auto res = details::byte_hex::to_hex( str );
    out << *res;
    return out;
}

int main_script1( )
{
    return 0;
}

int main_script0( )
{
    tx::output      outs[2];
    tx::output      prev_outs[1];
    tx::input       ins_sign[1];
    tx::outpoint    outpoint;
    tx::transaction tx;
    std::size_t     msg_len;
    tx::input       res_tx;

    const char msg_exp[] = "0100000001f3a27f485f9833c8318c490403307f"
                           "ef1397121b5dd8fe70777236e7371c4ef3000000"
                           "001976a9146bf19e55f94d986b4640c154d86469"
                           "934191951188acffffffff02e0fe7e0100000000"
                           "1976a91418ba14b3682295cb05230e31fecb0008"
                           "9240660888ace084b003000000001976a9146bf1"
                           "9e55f94d986b4640c154d86469934191951188ac"
                           "0000000001000000";

    outs[0].fill( 25100000, "18ba14b3682295cb05230e31fecb000892406608"_bin );
    outs[1].fill( 61900000, "6bf19e55f94d986b4640c154d864699341919511"_bin );
    outpoint.fill( "f34e1c37e736727770fed85d1b129713"
                   "ef7f300304498c31c833985f487fa2f3"_bin, 0 );
    prev_outs[0].fill( 87000000, "6bf19e55f94d986b4640c154d864699341919511"_bin );
    ins_sign[0].fill_signable( outpoint, prev_outs[0] );

    tx.tx_out.push_back( outs[0] );
    tx.tx_out.push_back( outs[1] );
    tx.tx_in.push_back( ins_sign[0] );
    tx.locktime = 0;
    tx.version = 1;
    msg_len = tx.size( tx::SIGHASH_ALL );
    std::string res;
    tx.serialize_to( tx::SIGHASH_ALL, res );

    std::cout << msg_exp << "\n";
    printhex(std::cout, res) << "\n";

    //res = *details::byte_hex::to_hex( res );
    auto h = hash::hash256::get_string( res.c_str( ), res.size( ) );

    auto k = crypto::ec_key::create_private( priv_bytes, sizeof(priv_bytes) );
    auto s = crypto::signature::hash_and_sign( h.c_str( ), h.size( ), k.get( ));

    auto der = s.to_der( k.get( ) );

    tx.tx_in[0].fill( outpoint, der,
                      std::string(pub_bytes, pub_bytes+sizeof(pub_bytes)),
                      tx::SIGHASH_ALL );

    res.clear( );
    tx.serialize_to( tx::SIGHASH_NON, res );

    std::cout << "\n";
    std::cout << etool::dumper::make<>::to_hex( res.c_str( ), res.size( ), "", " " )
              << "\n";

    return 0;
}

int main_script( )
{
    return main_script0( );

    const std::string message = "This is a very confidential message\n";
    auto k  = crypto::ec_key::create_private( priv_bytes, sizeof(priv_bytes) );
    auto signature = crypto::signature::hash_and_sign( message.c_str( ),
                                              message.size( ), k.get( ) );
    auto der = signature.to_der( k.get( ) );

    auto ms = slices::memory<std::uint8_t>( pub_bytes, sizeof(pub_bytes) );

    auto r = standarts::P2PKH_in( der, ms );

    auto out = dumper::make<>::to_hex( r.c_str( ), r.size( ), " ", "0x" );

    std::cout << out << "\n";

    return 0;
}

/*
01 00 00 00
01

F3 A2 7F 48 5F 98 33 C8
31 8C 49 04 03 30 7F EF
13 97 12 1B 5D D8 FE 70
77 72 36 E7 37 1C 4E F3

00 00 00 00

6B 48 30 45 02 21 00 D5
A5 5F 3E 18 2B D7 4C 97
4A AE 33 85 B6 CD AC A9
9F 3F A9 F6 3F E6 E9 85
46 D2 AF 86 38 0B E6 02
20 7E 8F 37 B2 21 B1 32
48 EA A4 A6 13 7E 1B 52
A6 2F C2 D5 1F E2 8B C5
38 83 11 D0 EF BE 69 AD
60 01 21 02 82 00 6E 93
98 A6 98 6E DA 61 FE 91
67 4C 3A 10 8C 39 94 75
BF 1E 73 8F 19 DF C2 DB
11 DB 1D 28

FF FF FF FF

02

E0 FE 7E 01 00 00 00 00

19 76 A9 14 18 BA 14 B3
68 22 95 CB 05 23 0E 31
FE CB 00 08 92 40 66 08
88 AC

E0 84 B0 03 00 00 00 00

19 76 A9 14 6B F1 9E 55
F9 4D 98 6B 46 40 C1 54
D8 64 69 93 41 91 95 11
88 AC

00 00 00 00
*/
