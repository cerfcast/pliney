#ifndef __CONSTANTS_HPP
#define __CONSTANTS_HPP

#include <cstdint>
#include <string>

namespace Pliney {
    const uint8_t IPV4_VERSION{0x4};
    const uint8_t IPV4_DEFAULT_HEADER_LENGTH_OCTETS{0x5};
    const uint8_t IPV4_DEFAULT_HEADER_LENGTH{20};

    const uint8_t IPV6_VERSION{0x6};
    const uint8_t IPV6_DEFAULT_HEADER_LENGTH{40};

    const uint8_t UDP_DEFAULT_HEADER_LENGTH{0x8};
    const uint8_t TCP_DEFAULT_HEADER_LENGTH{0x14};

    const uint8_t UDP_PROTOCOL{17};
    const uint8_t TCP_PROTOCOL{6};

    enum class Transport {
        UDP,
        TCP,
    };

    std::string to_string(const Transport &transport);
    Transport from_pisa_transport(uint8_t transport);
    uint8_t to_pisa_transport(const Transport &transport);

    enum class IpVersion {
        FOUR,
        SIX,
    };

    std::string to_string(const IpVersion &version);
    IpVersion from_pisa_version(uint8_t version);
    uint8_t to_pisa_version(const IpVersion &version);


}

#endif
