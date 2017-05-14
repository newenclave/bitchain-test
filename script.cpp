
#include <deque>
#include <cstdint>

namespace {

    namespace op {
        enum class code: std::uint8_t {
            OP_0     = 0,
            OP_FALSE = 0,
            OP_1     =  1 + 0x50,
            OP_2     =  2 + 0x50,
            OP_3     =  3 + 0x50,
            OP_4     =  4 + 0x50,
            OP_5     =  5 + 0x50,
            OP_6     =  6 + 0x50,
            OP_7     =  7 + 0x50,
            OP_8     =  8 + 0x50,
            OP_9     =  9 + 0x50,
            OP_10    = 10 + 0x50,
            OP_11    = 11 + 0x50,
            OP_12    = 12 + 0x50,
            OP_13    = 13 + 0x50,
            OP_14    = 14 + 0x50,
            OP_15    = 15 + 0x50,
            OP_16    = 16 + 0x50,
            OP_TRUE  = OP_1,
        };
    }

    class stack {
    public:
        using byte = std::uint8_t;
        using container_type = std::deque<byte>;

    private:
        container_type state_;
    };

}

int main_script( )
{
    return 0;
}
