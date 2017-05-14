#include <iostream>
#include <cstdint>
#include <deque>

namespace {

    namespace op {
        enum class code: std::uint8_t {
            OP_FALSE = 0,
            OP_TRUE  = 1,
        };
    }

    class stack {
        using byte = std::uint8_t;
    private:
        std::deque<byte> cont_;
    };


}

int main( )
{
    return 0;
}
