#include "../../include/Hooking.Patterns.h"

#include <cstring>
#include <iostream>
#include <iomanip>
#include <sstream>

#define PATTERN_CLEAR_BITS(addr) (addr & ~0x1)

int main()
{
std::cout << "Pattern: xmds" << std::endl;


    // Get the address of main
    uintptr_t begin = PATTERN_CLEAR_BITS((uintptr_t)main);
    uintptr_t end = begin + 0x04;

    unsigned char bytes[4];
    memcpy(bytes, (void*)begin, 4);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(2) << static_cast<int>(bytes[0])
        << std::setw(2) << static_cast<int>(bytes[1])
        << std::setw(2) << static_cast<int>(bytes[2])
        << std::setw(2) << static_cast<int>(bytes[3]);
    const char* bytecode = oss.str().c_str();
    
    // Find the pattern
    auto pattern = hook::pattern(begin, end, bytecode);

    std::cout << "Pattern: " << bytecode << std::endl;
    // Get the address
    if (!pattern.count_hint(1).empty())
    {
        auto address = pattern.get(0).get<uintptr_t>(0);
        // Print the address
        printf("Address: 0x%p\n", address);
    }
    else
    {
        printf("Pattern not found\n");
    }
    return 0;
}


