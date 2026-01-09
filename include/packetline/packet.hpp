#ifndef __PLINEY_PACKET_HPP
#define __PLINEY_PACKET_HPP

#include "packetline/constants.hpp"
#include "pisa/compilation.hpp"
#include <variant>

struct PlineyPacketIpHdr {
  Pliney::IpVersion version;
  size_t len;
  union {
    struct iphdr *ip;
    struct ip6_hdr *ip6;
  } hdr;
};

struct PlineyPacketIpOpts {
  size_t ip_opt_ext_hdr_raw_len{0};
  uint8_t *ip_opts_exts_hdr_raw{nullptr};
  pisa_ip_opts_exts_t ip_opts_exts_hdr{};
};

struct PlineyPacketTransportHdr {
  size_t transport_len{0};
  void *transport{nullptr};
  size_t transportoptionhdr_len{0};
  uint8_t *transportoptionhdr{nullptr};
};

struct RunnerPacketBody {
  size_t len{0};
  void *body{nullptr};
};

struct PlineyPacket {
  PlineyPacketIpHdr ip_packet;
  PlineyPacketIpOpts opts;
  PlineyPacketTransportHdr transport_packet;
  RunnerPacketBody body;

  static std::variant<PlineyPacket, std::string>
  from(const unique_pisa_program_t &pisa_program);

  static std::variant<PlineyPacket, std::string> from(const data_p data);
};

#endif