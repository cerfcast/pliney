#include "packetline/runner.hpp"
#include "packetline/constants.hpp"

#include "lib/logger.hpp"
#include "packetline/utilities.hpp"
#include "pisa/compilation.hpp"
#include "pisa/exthdrs.h"
#include "pisa/pisa.h"
#include "pisa/utils.h"

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <format>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <variant>


std::variant<RunnerPacket, std::string>
RunnerPacket::from(const pisa_ptr_value_t data) {
  RunnerPacket res{};

  // DO simple first: no handling special "things"

  // Check that what we have is an ethernet packet containing an IP packet.

  const struct ether_header *eth{
      reinterpret_cast<const struct ether_header *>(data.data)};

  if (eth->ether_type != htons(ETH_P_IP) &&
      eth->ether_type != htons(ETH_P_IPV6)) {
    return "Cannot create a RunnerPacket from a non-IP enclosing ethernet "
           "packet";
  }

  size_t parsing_offset{sizeof(struct ether_header)};
  const struct iphdr *iph{reinterpret_cast<const struct iphdr *>(
      WITH_OFFSET(data.data, parsing_offset))};

  auto transport_type{Pliney::Transport::UDP};

  if (iph->version == Pliney::IP4_VERSION) {
    Logger::ActiveLogger()->log(
        Logger::DEBUG, std::format("(From ethernet) found an IP v4 packet."));
    const struct iphdr *iph{reinterpret_cast<const struct iphdr *>(
        WITH_OFFSET(data.data, parsing_offset))};
    parsing_offset += Pliney::IPV4_BASE_HEADER_LENGTH;

    res.ip_packet.version = Pliney::IpVersion::FOUR;
    res.ip_packet.len = Pliney::IPV4_BASE_HEADER_LENGTH;
    res.ip_packet.hdr.ip =
        (struct iphdr *)calloc(res.ip_packet.len, sizeof(uint8_t));

    // Now, copy over the contents.
    // Do the copy here because it helps to know the IP version for final
    // processing (see below).
    memcpy(res.ip_packet.hdr.ip, iph, res.ip_packet.len);

    // Adjust the IP packet's total length to just the header size -- the
    // execution process will readjust (see above).
    res.ip_packet.hdr.ip->tot_len = htons(Pliney::IPV4_BASE_HEADER_LENGTH);

    transport_type = Pliney::from_native_transport(iph->protocol);

    // We assume that there are no options IPv4 options.

  } else {
    Logger::ActiveLogger()->log(
        Logger::DEBUG, std::format("(From ethernet) found an IP v6 packet."));
    const struct ip6_hdr *iph{reinterpret_cast<const struct ip6_hdr *>(
        WITH_OFFSET(data.data, parsing_offset))};

    parsing_offset += Pliney::IPV6_BASE_HEADER_LENGTH;
    res.ip_packet.version = Pliney::IpVersion::SIX;
    // TODO: Check.
    res.ip_packet.len = Pliney::IPV6_BASE_HEADER_LENGTH;
    res.ip_packet.hdr.ip6 =
        (struct ip6_hdr *)calloc(res.ip_packet.len, sizeof(uint8_t));

    // Now, copy over the contents.
    // Do the copy here because it helps to know the IP version for final
    // processing (see below).
    memcpy(res.ip_packet.hdr.ip6, iph, res.ip_packet.len);

    // Adjust the IP packet's total length to just the header size -- the
    // execution process will readjust (see above).
    res.ip_packet.hdr.ip6->ip6_plen = htons(0);

    // Now, let's see if there are IPv6 options.

    uint8_t next_header{iph->ip6_nxt};
    while (!is_protocol_transport(next_header)) {
      // There is an extension header.
      pisa_ip_opt_ext_t ext{};
      if (!from_raw_ip_opts_exts(WITH_OFFSET(data.data, parsing_offset),
                                 next_header, &ext, &next_header)) {
        Logger::ActiveLogger()->log(
            Logger::DEBUG, std::format("There was an error parsing an IPv6 extension header ... bad news."));
      }

      add_ip_opt_ext(&res.opts.ip_opts_exts_hdr, ext);

      parsing_offset += 2 + ext.len;
    }

    transport_type = Pliney::from_native_transport(next_header);
    res.ip_packet.hdr.ip6->ip6_nxt = next_header;
  }

  // Next, let's check out the transport!
  void *transport_start = WITH_OFFSET(data.data, parsing_offset);

  res.transport_packet.transport_len = transport_header_size(transport_type);
  res.transport_packet.transport = reinterpret_cast<void *>(
      calloc(res.transport_packet.transport_len, sizeof(uint8_t)));
  memcpy(res.transport_packet.transport, (uint8_t *)transport_start,
         res.transport_packet.transport_len);

  parsing_offset += res.transport_packet.transport_len;

  res.body.len = data.len - parsing_offset;
  res.body.body =
      reinterpret_cast<void *>(calloc(res.body.len, sizeof(uint8_t)));
  memcpy(res.body.body, WITH_OFFSET(data.data, parsing_offset), res.body.len);

  return res;
}

std::variant<RunnerPacket, std::string>
RunnerPacket::from(const unique_pisa_program_t &pisa_program) {
  RunnerPacket res{};
  ip_addr_t pisa_target_address{};
  Pliney::Transport pisa_pgm_transport_type{};

  if (!Runner::find_program_target_transport(pisa_program, pisa_target_address,
                                             pisa_pgm_transport_type)) {
    return "Could not find the target and/or transport in the PISA program";
  }

  auto pisa_pgm_ip_version{
      Pliney::from_pisa_version(pisa_target_address.family)};

  Logger::ActiveLogger()->log(Logger::DEBUG,
                              std::format("PISA program IP version: {}",
                                          to_string(pisa_pgm_ip_version)));
  Logger::ActiveLogger()->log(Logger::DEBUG,
                              std::format("PISA program transport type: {}",
                                          to_string(pisa_pgm_transport_type)));

  // Let's say that there is an IP header -- make one as big as legal
  // (appropriate to the type).
  res.ip_packet.len = pisa_pgm_ip_version == Pliney::IpVersion::FOUR
                          ? Pliney::IPV4_BASE_HEADER_LENGTH
                          : Pliney::IPV6_BASE_HEADER_LENGTH;
  res.ip_packet.hdr.ip =
      (struct iphdr *)calloc(res.ip_packet.len, sizeof(uint8_t));

  // Put some initial values into the packet.
  if (pisa_pgm_ip_version == Pliney::IpVersion::FOUR) {
    res.ip_packet.version = Pliney::IpVersion::FOUR;
    struct iphdr *typed_hdr = res.ip_packet.hdr.ip;
    typed_hdr->version = Pliney::IP4_VERSION;
    typed_hdr->ihl = Pliney::IPV4_DEFAULT_HEADER_LENGTH_OCTETS;
    typed_hdr->tot_len = htons(Pliney::IPV4_DEFAULT_HEADER_LENGTH_OCTETS * 4);
    if (pisa_pgm_transport_type == Pliney::Transport::TCP) {
      typed_hdr->protocol = IPPROTO_TCP;
    } else if (pisa_pgm_transport_type == Pliney::Transport::UDP) {
      typed_hdr->protocol = IPPROTO_UDP;
    } else if (pisa_pgm_transport_type == Pliney::Transport::ICMP) {
      typed_hdr->protocol = IPPROTO_ICMP;
    }
  } else {
    struct ip6_hdr *typed_hdr = res.ip_packet.hdr.ip6;
    res.ip_packet.version = Pliney::IpVersion::SIX;
    typed_hdr->ip6_vfc |= Pliney::IP6_VERSION << 4;
    if (pisa_pgm_transport_type == Pliney::Transport::TCP) {
      typed_hdr->ip6_nxt = IPPROTO_TCP;
    } else if (pisa_pgm_transport_type == Pliney::Transport::UDP) {
      typed_hdr->ip6_nxt = IPPROTO_UDP;
    } else if (pisa_pgm_transport_type == Pliney::Transport::ICMP) {
      typed_hdr->ip6_nxt = IPPROTO_ICMP;
    }
  }

  // Let's say that there is a transport header -- make one of the appropriate
  // size.
  res.transport_packet.transport_len =
      transport_header_size(pisa_pgm_transport_type);
  res.transport_packet.transport =
      (void *)calloc(res.transport_packet.transport_len, sizeof(uint8_t));

  return res;
}
