#include "packetline/constants.hpp"
#include "pisa/pisa.h"
#include <netinet/in.h>
#include <utility>

namespace Pliney {
std::string to_string(const Pliney::Transport &transport) {
  switch (transport) {
    case Pliney::Transport::UDP: {
      return "UDP";
    }
    case Pliney::Transport::TCP: {
      return "TCP";
    }
    case Pliney::Transport::ICMP: {
      return "ICMP";
    }
    default:
      std::unreachable();
  }
}

Pliney::Transport from_pisa_transport(uint8_t transport) {
  switch (transport) {
    case PLINEY_TCP: {
      return Pliney::Transport::TCP;
    }
    case PLINEY_UDP: {
      return Pliney::Transport::UDP;
    }
    case PLINEY_ICMP: {
      return Pliney::Transport::ICMP;
    }
    default:
      std::unreachable();
  }
}

uint8_t to_pisa_transport(const Transport &transport) {
  switch (transport) {
    case Pliney::Transport::TCP: {
      return PLINEY_TCP;
    }
    case Pliney::Transport::UDP: {
      return PLINEY_UDP;
    }
    case Pliney::Transport::ICMP: {
      return PLINEY_ICMP;
    }
    default:
      std::unreachable();
  }
}

uint8_t to_native_transport(const Transport &transport) {
  switch (transport) {
    case Pliney::Transport::TCP: {
      return IPPROTO_TCP;
    }
    case Pliney::Transport::UDP: {
      return IPPROTO_UDP;
    }
    case Pliney::Transport::ICMP: {
      return IPPROTO_ICMP;
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
    case PLINEY_IPVERSION4: {
      return Pliney::IpVersion::FOUR;
    }
    case PLINEY_IPVERSION6: {
      return Pliney::IpVersion::SIX;
    }
    default:
      std::unreachable();
  }
}

uint8_t to_pisa_version(const IpVersion &version) {
  switch (version) {
    case Pliney::IpVersion::FOUR: {
      return PLINEY_IPVERSION4;
    }
    case Pliney::IpVersion::SIX: {
      return PLINEY_IPVERSION6;
    }
    default:
      std::unreachable();
  }
}
} // namespace Pliney