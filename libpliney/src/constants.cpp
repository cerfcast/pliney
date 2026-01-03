#include "packetline/constants.hpp"
#include "pisa/pisa.h"
#include <lib/safety.hpp>
#include <netinet/in.h>

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
    case Pliney::Transport::ICMP6: {
      return "ICMPv6";
    }
    default:
      PLINEY_UNREACHABLE
  }
}

Pliney::Transport from_native_transport(uint8_t transport) {
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
    case PLINEY_ICMP6: {
      return Pliney::Transport::ICMP6;
    }
    default:
      PLINEY_UNREACHABLE
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
    case Pliney::Transport::ICMP6: {
      return PLINEY_ICMP6;
    }
    default:
      PLINEY_UNREACHABLE
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
    case Pliney::Transport::ICMP6: {
      return IPPROTO_ICMPV6;
    }
    default:
      PLINEY_UNREACHABLE
  }
}

std::string to_string(const Pliney::IpVersion &version) {
  switch (version) {
    case Pliney::IpVersion::FOUR: {
      return "IP Version 4";
    }
    case Pliney::IpVersion::SIX: {
      return "IP Version 6";
    }
    default:
      PLINEY_UNREACHABLE
  }
}

Pliney::IpVersion from_native_version(uint8_t version) {
  switch (version) {
    case IP4_VERSION: {
      return Pliney::IpVersion::FOUR;
    }
    case IP6_VERSION: {
      return Pliney::IpVersion::SIX;
    }
    default:
      PLINEY_UNREACHABLE
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
      PLINEY_UNREACHABLE
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
      PLINEY_UNREACHABLE
  }
}
} // namespace Pliney