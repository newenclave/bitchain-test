#include <iostream>
#include <cstdint>
#include <deque>

#include "etool/details/byte_order.h"

namespace {

    namespace op {
        enum class code: std::uint8_t {
            FALSE    = 0,
            TRUE     = 1,
            UINT8    = 2,
            UINT16   = 3,
            UINT32   = 4,
            UINT64   = 5,
        };
    }

    class stack {
        using byte = std::uint8_t;
    public:

        void push( byte b )
        {
            cont_.push_front( b );
        }

        template <typename ItrT>
        void push( ItrT b, ItrT e )
        {
            cont_.insert( cont_.begin( ), b, e );
        }

        void pop( )
        {
            cont_.pop_front( );
        }

        void pop( size_t count )
        {
            cont_.erase( cont_.begin( ), std::next(cont_.begin( ), count) );
        }

        void read( byte *to, size_t count )
        {
            std::copy( cont_.begin( ), std::next(cont_.begin( ), count), to );
        }

    private:
        std::deque<byte> cont_;
    };

    struct element {
        virtual
        void push( stack & ) const = 0;

        virtual
        void read( stack & ) = 0;

        virtual
        std::uint8_t code( ) const = 0;

        virtual
        std::string as_bytes( ) const = 0;

        virtual
        std::uint8_t  as_uint8( ) const = 0;

        virtual
        std::uint16_t as_uint16( ) const = 0;

        virtual
        std::uint32_t as_uint32( ) const = 0;

        virtual
        std::uint64_t as_uint64( ) const = 0;

    };

    template <typename T, op::code>
    class uint {

        using llbytes = etool::details::byte_order_little<T>;
        using byte    = std::uint8_t;

    public:

        void push( stack &s )
        {
            byte b[sizeof(T)];
            llbytes::write( val_, b );
            s.push( b[0], b[sizeof(T)] );
        }

        void read( stack &s )
        {
            byte b[sizeof(T)];
            s.read( b, sizeof(T) );
            val_ = llbytes::read( b );
        }

        void pop( stack &s )
        {
            s.pop( sizeof(T) );
        }

    private:
        T val_;
    };

}

int main( )
{
    return 0;
}
