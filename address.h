#ifndef ADDRESS_H
#define ADDRESS_H

#include <string>

#include "crypto.h"
#include "base58.h"

#include "etool/details/result.h"

namespace bchain { namespace address {

    // Wallet Import Format
    struct wif {

        using result_type = etool::detail::result<std::string, const char *>;

        enum {
            VERSION_MAINNET  = 0x80,
            VERSION_TESTNET3 = 0xEF,
        };

        static
        std::string create( const crypto::ec_key &k, std::uint8_t version )
        {
            auto private_bytes = k.get_private_bytes( );
            return create( private_bytes, version, k.get_conv_compressed( ) );
        }

        static
        std::string create( const std::string &private_bytes,
                            std::uint8_t version, bool compress_public )
        {
            using cu8 = const std::uint8_t;
            auto u8data = reinterpret_cast<cu8 *>(private_bytes.c_str( ));
            return create( u8data, private_bytes.size( ), version,
                           compress_public );
        }

        static
        std::string create( const std::uint8_t *priv_bytes, size_t plen,
                            std::uint8_t version, bool compress_public )
        {
            std::string res;

            res.push_back( static_cast<char>(version) );
            res.append( &priv_bytes[0], &priv_bytes[plen] );

            if( compress_public ) {
                res.push_back( 0x01 );
            }

            hash::hash256::digit_block digit;
            hash::hash256::get( digit, res.c_str( ), res.size( ) );
            res.append( &digit[0], &digit[4] );

            return base58::encode( res );
        }
    };

    // pay-to-public-key-hash
    struct p2pkh {

        using result_type = etool::detail::result<std::string, const char *>;

        enum {
            VERSION_MAINNET  = 0x00,
            VERSION_TESTNET3 = 0x6F,
        };

        static
        result_type from_wif( const std::string &w )
        {
            using err = result_type::error_arg;
            using val = result_type::value_arg;

            /// uncompressed = version (1)
            ///              + private bytes (32)
            ///              + hash (4) = 37
            /// compressed   = version (1)
            ///              + private bytes (32)
            ///              + compressed flag (1)
            ///              + hash (4) = 38

            enum { UNCOMPRESSED_SIZE = 37, COMPRESSED_SIZE = 38 };

            auto decoded = base58::decode( w );

            if(  ( decoded.size( ) != UNCOMPRESSED_SIZE )
              && ( decoded.size( ) != COMPRESSED_SIZE ) )
            {
                return result_type(err("Invalid WIF. Bad length"));
            }

            std::uint8_t prefix = static_cast<std::uint8_t>(decoded[0]);

            switch (prefix) {
            case wif::VERSION_MAINNET:
                prefix = VERSION_MAINNET;
                break;
            case wif::VERSION_TESTNET3:
                prefix = VERSION_TESTNET3;
                break;
            default:
                return result_type(err("Invalid WIF. Bad version"));
            }

            hash::sha256::digit_block digit;
            size_t body_len = decoded.size( ) - 4;
            hash::hash256::get( digit, decoded.c_str( ), body_len );

            if(  digit[0] != static_cast<std::uint8_t>(decoded[body_len + 0])
              || digit[1] != static_cast<std::uint8_t>(decoded[body_len + 1])
              || digit[2] != static_cast<std::uint8_t>(decoded[body_len + 2])
              || digit[3] != static_cast<std::uint8_t>(decoded[body_len + 3]) )
            {
                return result_type(err("Invalid WIF. Bad hash"));
            }
            auto k = crypto::ec_key::create_private( decoded.c_str( ) + 1, 32 );
            if( !k ) {
                return result_type(err("Invalid WIF. Bad private value"));
            }
            k.set_conv_compressed( decoded.size( ) == COMPRESSED_SIZE );
            return result_type(val(create(k, prefix)));
        }

        static
        std::string create( crypto::ec_key &k, std::uint8_t prefix )
        {
            auto pub_bytes = k.get_public_bytes( );
            return create( pub_bytes, prefix );
        }

        static
        std::string create( const std::string &pub_bytes, std::uint8_t prefix )
        {
            using cu8 = const std::uint8_t;
            auto u8data = reinterpret_cast<cu8 *>(pub_bytes.c_str( ));
            return create( u8data, pub_bytes.size( ), prefix );
        }

        static
        std::string create( const std::uint8_t *pub_bytes, size_t len,
                            std::uint8_t prefix )
        {
            std::string res;
            res.push_back( static_cast<char>(prefix) );

            hash::hash160::append( pub_bytes, len, res );

            hash::hash256::digit_block digit;
            hash::hash256::get( digit, res.c_str( ), res.size( ) );
            res.append( &digit[0], &digit[4] );

            return base58::encode( res );
        }
    };

}}

#endif // ADDRESS_H
