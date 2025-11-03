#ifndef __CONSTANTS_HPP
#define __CONSTANTS_HPP

#include <cstdint>

namespace Pliney {
    const uint8_t IPV4_VERSION{0x4};
    const uint8_t IPV4_DEFAULT_HEADER_LENGTH{0x5};

    const uint8_t IPV6_VERSION{0x6};

    const uint8_t UDP_DEFAULT_HEADER_LENGTH{0x8};
    const uint8_t TCP_DEFAULT_HEADER_LENGTH{0x14};
}
#endif
