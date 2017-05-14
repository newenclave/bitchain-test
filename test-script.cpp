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

    private:
        std::deque<byte> cont_;
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

    private:
        T val_;
    };

}

int main( )
{
    return 0;
}
