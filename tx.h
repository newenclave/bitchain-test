#ifndef BLOCK_CHAIN_TX_H
#define BLOCK_CHAIN_TX_H

#include <cstdint>
#include <vector>
#include <deque>
#include <array>
#include <algorithm>

#include "etool/details/byte_order.h"
#include "etool/sizepack/blockchain_varint.h"
#include "etool/details/byte_hex.h"

namespace bchain { namespace tx {

    enum sighash {
        SIGHASH_NON = 0,
        SIGHASH_ALL = 1,
    };

    struct order {
        template <typename T>
        using little = etool::details::byte_order_little<T>;

        template <typename T>
        static
        void reverse( T *begin, std::size_t len )
        {
            auto middle = len / 2;
            for( std::size_t i =0; i<middle; ++i ) {
                std::swap(begin[i], begin[len - i - 1]);
            }
        }
    };

    struct ser {

        static
        std::size_t varint_size( std::size_t len )
        {
            using bo_var = etool::sizepack::blockchain_varint;
            return bo_var::result_length( len );
        }

        static
        void append32( std::uint32_t val, std::string &out )
        {
            using bo32 = order::little<std::uint32_t>;
            auto s = out.size( );
            out.resize( s + sizeof(std::uint32_t) );
            bo32::write( val, &out[s] );
        }

        static
        void append64( std::uint64_t val, std::string &out )
        {
            using bo64 = order::little<std::uint64_t>;
            auto s = out.size( );
            out.resize( s + sizeof(std::uint64_t) );
            bo64::write( val, &out[s] );
        }

        static
        void append_var( std::uint64_t val, std::string &out )
        {
            using bo_var = etool::sizepack::blockchain_varint;
            bo_var::append( val, out );
        }
    };

    struct output {

        std::uint64_t value;
        std::vector<std::uint8_t> script;

        std::size_t size( ) const
        {
            std::size_t res = sizeof(value);
            res += ser::varint_size( script.size( ) );
            res += script.size( );
            return res;
        }

        void serialize_to( std::string &out ) const
        {
            ser::append64( value, out );
            ser::append_var( script.size( ), out );
            out.append( script.begin( ), script.end( ) );
        }

        void fill( std::uint64_t val, const std::string &hash160 )
        {
            std::vector<std::uint8_t> tmp;
            tmp.push_back( 0x76 );
            tmp.push_back( 0xa9 );
            tmp.push_back( 0x14 );
            tmp.insert( tmp.end( ), hash160.begin( ), hash160.end( ) );
            tmp.push_back( 0x88 );
            tmp.push_back( 0xac );

            script.swap(tmp);
            value = val;
        }
    };

    struct outpoint {

        std::array<std::uint8_t, 32> txid; /// hash256
        std::uint32_t index;

        std::size_t size( ) const
        {
            std::size_t res = 32;
            res += sizeof( index );
            return res;
        }

        void serialize_to( std::string &out ) const
        {
            out.append( txid.begin( ), txid.end( ) );
            ser::append32( index, out );
        }

        void fill( const std::string &tid, std::uint32_t idx )
        {
            std::copy( tid.begin( ), tid.end( ), txid.begin( ) );
            order::reverse( txid.data( ), txid.size( ) );
            index = idx;
        }
    };

    struct input {
        outpoint op;
        std::vector<std::uint8_t> script;
        std::uint32_t seq;

        std::size_t size( ) const
        {
            std::size_t res = op.size( );
            res += ser::varint_size( script.size( ) );
            res += script.size( );
            res += sizeof(seq);
            return res;
        }

        void serialize_to( std::string &out ) const
        {
            op.serialize_to( out );
            ser::append_var( script.size( ), out );
            out.append( script.begin( ), script.end( ) );
            ser::append32( seq, out );
        }

        void fill( outpoint out, const std::string &sig,
                   const std::string &pub, sighash flag )
        {
            std::vector<std::uint8_t> tmp;
            tmp.push_back( static_cast<std::uint8_t>(sig.size( ) + 1) );
            tmp.insert( tmp.end( ), sig.begin( ), sig.end( ) );
            tmp.push_back( static_cast<std::uint8_t>(flag) );
            tmp.push_back( static_cast<std::uint8_t>(pub.size( ) ) );
            tmp.insert( tmp.end( ), pub.begin( ), pub.end( ) );

            script.swap( tmp );
            op = std::move(out);
            seq = 0xffffffff;
        }

        void fill_signable( outpoint opoint, output oput )
        {
            op = std::move(opoint);
            script.swap( oput.script );
            seq = 0xffffffff;
        }

        void fill_truncated( outpoint opoint )
        {
            op = std::move(opoint);
            script.clear( );
            seq = 0xffffffff;
        }
    };

    struct transaction {

        std::uint32_t       version = 1;
        std::deque<input>   tx_in;
        std::deque<output>  tx_out;
        std::uint32_t       locktime = 0;

        std::size_t size( sighash flags ) const
        {
            std::size_t res = 0;

            res += sizeof( version );
            res += ser::varint_size( tx_in.size( ) );
            for( auto &i: tx_in ) {
                res += i.size( );
            }

            res += ser::varint_size( tx_out.size( ) );
            for( auto &o: tx_out ) {
                res += o.size( );
            }

            res += sizeof(locktime);

            if( flags ) {
                res += sizeof(std::uint32_t);
            }

            return res;
        }

        void serialize_to( sighash flags, std::string &out ) const
        {
            ser::append32( version, out );

            ser::append_var( tx_in.size( ), out );
            for( auto &i: tx_in ) {
                i.serialize_to( out );
            }

            ser::append_var( tx_out.size( ), out );
            for( auto &o: tx_out ) {
                o.serialize_to( out );
            }

            ser::append32( locktime, out );

            if( flags ) {
                ser::append32( flags, out );
            }
        }
    };



}}

#endif // TX_H
