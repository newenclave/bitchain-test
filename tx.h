#ifndef BLOCK_CHAIN_TX_H
#define BLOCK_CHAIN_TX_H

#include <cstdint>
#include <vector>
#include <array>

#include "etool/details/byte_order.h"
#include "etool/sizepack/blockchain_varint.h"

namespace bchain { namespace tx {

    enum class sighash {
        SIGHASH_ALL = 1,
    };

    struct output {
        std::uint64_t value;
        std::vector<std::uint8_t> script;
    };

    struct outpoint {
        std::array<std::uint8_t, 32> txid; /// hash256
        std::uint32_t index;
    };

    struct input {
        outpoint op;
        std::vector<std::uint8_t> script;
        std::uint32_t seq;
    };

    struct transaction {
        std::uint32_t version = 1;
        input         tx_in;
        output        tx_out;
        std::uint32_t locktype = 0;

        void append32( std::uint32_t val, std::string &out ) const
        {
            using bo32 = etool::details::byte_order_little<std::uint32_t>;
            auto s = out.size( );
            out.resize( s + sizeof(std::uint32_t) );
            bo32::write( val, &out[s] );
        }

        void append_var( std::uint64_t val, std::string &out ) const
        {
            using bo_var = etool::sizepack::blockchain_varint;
            bo_var::pack( val, out );
        }

        std::string serialize( sighash flags ) const
        {
            std::string res;
            append32( version, res );
            //append_var(  )
            return res;
        }
    };



}}

#endif // TX_H
