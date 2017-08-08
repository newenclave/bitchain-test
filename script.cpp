
#include <deque>
#include <cstdint>
#include <string>
#include <iostream>

#include "etool/details/byte_order.h"
#include "etool/dumper/dump.h"
#include "etool/slices/memory.h"

#include "crypto.h"

#include "hash.h"

namespace {

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
                res.push_back( op::to_byte(op::code::OP_PUSHDATA1) );
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
            res.push_back(out[1]);
            res.push_back(out[0]);

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
            res.push_back(out[3]);
            res.push_back(out[2]);
            res.push_back(out[1]);
            res.push_back(out[0]);

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

int main_script( )
{

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
