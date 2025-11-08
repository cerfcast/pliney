#include "packetline/constants.hpp"
#include "pisa/pisa.h"
#include <utility>

namespace Pliney {
std::string to_string(const Pliney::Transport &transport) {
  switch (transport) {
    case Pliney::Transport::UDP: {
      return "UDP";
      break;
    }
    case Pliney::Transport::TCP: {
      return "IP";
    }
    default:
      std::unreachable();
  }
}

Pliney::Transport from_pisa_transport(uint8_t transport) {
  switch (transport) {
    case INET_STREAM: {
      return Pliney::Transport::TCP;
    }
    case INET_DGRAM: {
      return Pliney::Transport::UDP;
    }
    default:
      std::unreachable();
  }
}

uint8_t to_pisa_transport(const Transport &transport) {
  switch (transport) {
    case Pliney::Transport::TCP: {
      return INET_STREAM;
    }
    case Pliney::Transport::UDP: {
      return INET_DGRAM;
    }
    default:
      std::unreachable();
  }
}

std::string to_string(const IpVersion &version);
IpVersion from_pisa_version(uint8_t version);
uint8_t to_pisa_version(const IpVersion &version);

std::string to_string(const Pliney::IpVersion &version) {
  switch (version) {
    case Pliney::IpVersion::FOUR: {
      return "IP Version 4";
      break;
    }
    case Pliney::IpVersion::SIX: {
      return "IP Version 6";
    }
    default:
      std::unreachable();
  }
}

Pliney::IpVersion from_pisa_version(uint8_t version) {
  switch (version) {
    case INET_ADDR_V4: {
      return Pliney::IpVersion::FOUR;
    }
    case INET_ADDR_V6: {
      return Pliney::IpVersion::SIX;
    }
    default:
      std::unreachable();
  }
}

uint8_t to_pisa_version(const IpVersion &version) {
  switch (version) {
    case Pliney::IpVersion::FOUR: {
      return INET_ADDR_V4;
    }
    case Pliney::IpVersion::SIX: {
      return INET_ADDR_V6;
    }
    default:
      std::unreachable();
  }
}
} // namespace Pliney