#ifndef BLOCK_CHAIN_TX_H
#define BLOCK_CHAIN_TX_H

#include <cstdint>
#include <vector>
#include <deque>
#include <array>

#include "etool/details/byte_order.h"
#include "etool/sizepack/blockchain_varint.h"

namespace bchain { namespace tx {

    enum sighash {
        SIGHASH_ALL = 1,
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
            using bo32 = etool::details::byte_order_little<std::uint32_t>;
            auto s = out.size( );
            out.resize( s + sizeof(std::uint32_t) );
            bo32::write( val, &out[s] );
        }

        static
        void append64( std::uint64_t val, std::string &out )
        {
            using bo64 = etool::details::byte_order_little<std::uint64_t>;
            auto s = out.size( );
            out.resize( s + sizeof(std::uint64_t) );
            bo64::write( val, &out[s] );
        }

        static
        void append_var( std::uint64_t val, std::string &out )
        {
            using bo_var = etool::sizepack::blockchain_varint;
            bo_var::pack( val, out );
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
            out.append( op.txid.begin( ), op.txid.end( ) );
            ser::append32( op.index, out );
            ser::append32( static_cast<std::uint32_t>(script.size( )), out );
            out.append( script.begin( ), script.end( ) );
            ser::append32( seq, out );
        }
    };

    struct transaction {

        std::uint32_t version = 1;
        std::deque<input>  tx_in;
        std::deque<output> tx_out;
        std::uint32_t locktype = 0;

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

            res += sizeof(locktype);

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

            ser::append32( locktype, out );

            if( flags ) {
                ser::append32( flags, out );
            }
        }
    };



}}

#endif // TX_H
