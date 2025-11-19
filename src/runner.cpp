#include "packetline/runner.hpp"
#include "lib/ip.hpp"
#include "packetline/constants.hpp"

#include "lib/logger.hpp"
#include "packetline/utilities.hpp"
#include "pisa/compilation.hpp"
#include "pisa/exthdrs.h"
#include "pisa/pisa.h"
#include "pisa/plugin.h"
#include "pisa/utils.h"

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <format>
#include <fstream>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <optional>
#include <regex>
#include <sys/socket.h>
#include <sys/types.h>

#include <iostream>

#define PISA_COWARDLY_VERSION_CHECK(expected, actual, message)                 \
  if (actual != expected) {                                                    \
    Logger::ActiveLogger()->log(Logger::WARN, std::format(message));           \
    break;                                                                     \
  }

#define PISA_WARN_NOOP(op, fr)                                                 \
  {                                                                            \
    Logger::ActiveLogger()->log(Logger::WARN,                                  \
                                std::format("{} is a noop for {}", op, fr));   \
    break;                                                                     \
  }

bool Runner::find_program_target_transport(const unique_pisa_program_t &program,
                                           ip_addr_t &pisa_target_address,
                                           Pliney::Transport &transport) {
  pisa_value_t pisa_transport_value = {.tpe = BYTE};
  pisa_value_t pgm_target;
  pisa_value_t pgm_target_port;

  // First, find the destination. The program must set one.
  if (!pisa_program_find_target_value(program.get(), &pgm_target)) {
    Logger::ActiveLogger()->log(
        Logger::ERROR, "Could not find the target address in the PISA program");
    return false;
  }
  // Second, find the destination port. The program may set one.
  if (!pisa_program_find_target_value(program.get(), &pgm_target_port)) {
    Logger::ActiveLogger()->log(
        Logger::ERROR,
        "Could not find the target address int the PISA program");
    return false;
  }

  pisa_target_address = pgm_target.value.ipaddr;
  pisa_target_address.port = pgm_target.value.ipaddr.port;

  // Now, find out the transport type. The program must set one.
  if (!pisa_program_find_meta_value(program.get(), "TRANSPORT",
                                    &pisa_transport_value)) {
    Logger::ActiveLogger()->log(
        Logger::ERROR, "Could not find the transport type in the PISA program");
    return false;
  }
  transport = Pliney::from_pisa_transport(pisa_transport_value.value.byte);

  return true;
}

bool PacketRunner::execute(Compilation &compilation) {

  if (!compilation) {
    return false;
  }

  auto &program = compilation.program;

  pisa_value_t pgm_body{};
  ip_addr_t pisa_target_address{};
  Pliney::Transport pisa_pgm_transport_type{};

  if (!find_program_target_transport(program, pisa_target_address,
                                     pisa_pgm_transport_type)) {
    compilation.error =
        "Could not find the target and/or transport in the PISA program";
    return false;
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
  size_t iphdr_len{pisa_pgm_ip_version == Pliney::IpVersion::FOUR
                       ? Pliney::IPV4_DEFAULT_HEADER_LENGTH
                       : Pliney::IPV6_DEFAULT_HEADER_LENGTH};
  void *iphdr{(void *)calloc(iphdr_len, sizeof(uint8_t))};

  // Put some initial values into the packet.
  if (pisa_pgm_ip_version == Pliney::IpVersion::FOUR) {
    struct iphdr *typed_hdr = (struct iphdr *)iphdr;
    typed_hdr->version = Pliney::IPV4_VERSION;
    typed_hdr->ihl = Pliney::IPV4_DEFAULT_HEADER_LENGTH_OCTETS;
    if (pisa_pgm_transport_type == Pliney::Transport::TCP) {
      typed_hdr->protocol = IPPROTO_TCP;
    } else if (pisa_pgm_transport_type == Pliney::Transport::UDP) {
      typed_hdr->protocol = IPPROTO_UDP;
    } else if (pisa_pgm_transport_type == Pliney::Transport::ICMP) {
      typed_hdr->protocol = IPPROTO_ICMP;
    }
  } else {
    struct ip6_hdr *typed_hdr = (struct ip6_hdr *)iphdr;
    typed_hdr->ip6_vfc |= Pliney::IPV6_VERSION << 4;
    if (pisa_pgm_transport_type == Pliney::Transport::TCP) {
      typed_hdr->ip6_nxt = IPPROTO_TCP;
    } else if (pisa_pgm_transport_type == Pliney::Transport::UDP) {
      typed_hdr->ip6_nxt = IPPROTO_UDP;
    } else if (pisa_pgm_transport_type == Pliney::Transport::ICMP) {
      typed_hdr->ip6_nxt = IPPROTO_ICMP;
    }
  }

  // There could be some options that exist between the header and the
  // transport!
  size_t ip_opt_ext_hdr_raw_len{0};
  uint8_t *ip_opts_exts_hdr_raw{};
  pisa_ip_opts_exts_t ip_opts_exts_hdr{};

  // Let's say that there is a transport header -- make one of the appropriate
  // size.
  size_t transport_len{transport_header_size(pisa_pgm_transport_type)};
  void *transport{(void *)calloc(transport_len, sizeof(uint8_t))};

  size_t transportoptionhdr_len{0};
  uint8_t *transportoptionhdr{nullptr};

  // And, now let's follow instructions.
  for (size_t insn_idx{0}; insn_idx < program->inst_count; insn_idx++) {
    switch (program->insts[insn_idx].op) {
      case SET_META: {
        Logger::ActiveLogger()->log(
            Logger::DEBUG,
            std::format("SET_META is a no-op for Packet Runner."));
        break;
      } // SET_META
      case SET_TRANSPORT_EXTENSION: {
        // Because this replaces what was there before, release anything that
        // earlier!
        if (transportoptionhdr) {
          free(transportoptionhdr);
          transportoptionhdr_len = 0;
        }
        transportoptionhdr_len = program->insts[insn_idx].value.value.ptr.len;
        transportoptionhdr =
            (uint8_t *)calloc(transportoptionhdr_len, sizeof(uint8_t));
        memcpy(transportoptionhdr,
               program->insts[insn_idx].value.value.ptr.data,
               transportoptionhdr_len);
      } // SET_TRANSPORT_EXTENSION
      case ADD_IP_OPT_EXT: {
        if (program->insts[insn_idx].value.tpe == IP_EXT) {
          auto ip_ext{program->insts[insn_idx].value.value.ext};
          add_ip_opt_ext(&ip_opts_exts_hdr, ip_ext);
        } else {
          Logger::ActiveLogger()->log(
              Logger::ERROR, std::format("IP Options are not yet supported"));
        }
        break;
      } // ADD_IP_OPT_EXT
      case SET_FIELD: {
        switch (program->insts[insn_idx].fk.field) {
          case ICMP_CODE: {
            PISA_COWARDLY_VERSION_CHECK(
                Pliney::Transport::ICMP, pisa_pgm_transport_type,
                "Will not set an ICMP field on a non-ICMP PISA program");
            struct icmphdr *typed_hdr = (struct icmphdr *)transport;
            typed_hdr->code = program->insts[insn_idx].value.value.byte;
            break;
          }
          case ICMP_TYPE: {
            PISA_COWARDLY_VERSION_CHECK(
                Pliney::Transport::ICMP, pisa_pgm_transport_type,
                "Will not set an ICMP field on a non-ICMP PISA program");
            struct icmphdr *typed_hdr = (struct icmphdr *)transport;
            typed_hdr->type = program->insts[insn_idx].value.value.byte;
            break;
          }
          case ICMP_DEPENDS: {
            PISA_COWARDLY_VERSION_CHECK(
                Pliney::Transport::ICMP, pisa_pgm_transport_type,
                "Will not set an ICMP field on a non-ICMP PISA program");
            struct icmphdr *typed_hdr = (struct icmphdr *)transport;
            typed_hdr->un.echo.id =
                program->insts[insn_idx].value.value.four_bytes;
            typed_hdr->un.echo.sequence =
                program->insts[insn_idx].value.value.four_bytes >> 16;
            break;
          }
          case IPV6_TARGET_PORT:
          case IPV4_TARGET_PORT: {
            if (!transport_has_port(pisa_pgm_transport_type)) {
              PISA_WARN_NOOP("Setting the target port",
                             to_string(pisa_pgm_transport_type));
            }
            if (pisa_pgm_transport_type == Pliney::Transport::TCP) {
              struct tcphdr *typed_hdr = (struct tcphdr *)transport;
              typed_hdr->dest =
                  program->insts[insn_idx].value.value.ipaddr.port;
            } else {
              struct udphdr *typed_hdr = (struct udphdr *)transport;
              typed_hdr->dest =
                  program->insts[insn_idx].value.value.ipaddr.port;
            }
            break;
          }
          case IPV4_SOURCE_PORT:
          case IPV6_SOURCE_PORT: {
            if (!transport_has_port(pisa_pgm_transport_type)) {
              PISA_WARN_NOOP("Setting the target port",
                             to_string(pisa_pgm_transport_type));
            }
            if (pisa_pgm_transport_type == Pliney::Transport::TCP) {
              if (pisa_pgm_transport_type == Pliney::Transport::TCP) {
                struct tcphdr *typed_hdr = (struct tcphdr *)transport;
                typed_hdr->source =
                    program->insts[insn_idx].value.value.ipaddr.port;
              } else {
                struct udphdr *typed_hdr = (struct udphdr *)transport;
                typed_hdr->source =
                    program->insts[insn_idx].value.value.ipaddr.port;
              }
            }
            break;
          }
          case IPV4_TARGET: {
            PISA_COWARDLY_VERSION_CHECK(
                Pliney::IpVersion::FOUR, pisa_pgm_ip_version,
                "Will not set an IPv4 target on a non-IPv4 PISA program.");

            struct iphdr *typed_hdr = (struct iphdr *)iphdr;
            typed_hdr->daddr =
                program->insts[insn_idx].value.value.ipaddr.addr.ipv4.s_addr;

            break;
          }
          case IPV6_TARGET: {
            PISA_COWARDLY_VERSION_CHECK(
                Pliney::IpVersion::SIX, pisa_pgm_ip_version,
                "Will not set an IPv6 target on a non-IPv6 PISA program.");
            struct ip6_hdr *typed_hdr = (struct ip6_hdr *)iphdr;
            typed_hdr->ip6_dst =
                program->insts[insn_idx].value.value.ipaddr.addr.ipv6;
            break;
          }
          case IPV4_SOURCE: {
            PISA_COWARDLY_VERSION_CHECK(
                Pliney::IpVersion::FOUR, pisa_pgm_ip_version,
                "Will not set an IPv4 target on a non-IPv4 PISA program.");

            struct iphdr *typed_hdr = (struct iphdr *)iphdr;
            typed_hdr->saddr =
                program->insts[insn_idx].value.value.ipaddr.addr.ipv4.s_addr;
            break;
          }
          case IPV6_SOURCE: {
            PISA_COWARDLY_VERSION_CHECK(
                Pliney::IpVersion::SIX, pisa_pgm_ip_version,
                "Will not set an IPv6 target on a non-IPv6 PISA program.");
            struct ip6_hdr *typed_hdr = (struct ip6_hdr *)iphdr;
            typed_hdr->ip6_src =
                program->insts[insn_idx].value.value.ipaddr.addr.ipv6;
            break;
          }

          case APPLICATION_BODY: {
            PISA_COWARDLY_VERSION_CHECK(
                PTR, program->insts[insn_idx].value.tpe,
                ("Will not set a body from a non-pointer value in a "
                 "PISA program."));
            pgm_body = program->insts[insn_idx].value;

            // Update the total length field of the IP header.
            if (pisa_pgm_ip_version == Pliney::IpVersion::FOUR) {
              struct iphdr *typed_hdr = (struct iphdr *)iphdr;
              typed_hdr->tot_len =
                  htons((typed_hdr->ihl * 4) + pgm_body.value.ptr.len);
            } else {
              struct ip6_hdr *typed_hdr = (struct ip6_hdr *)iphdr;
              typed_hdr->ip6_plen = htons(pgm_body.value.ptr.len);
            }

            // Update the length of the transport (if udp)!
            if (pisa_pgm_transport_type == Pliney::Transport::UDP) {
              struct udphdr *typed_hdr = (struct udphdr *)transport;
              typed_hdr->len = htons(pgm_body.value.ptr.len +
                                     Pliney::UDP_DEFAULT_HEADER_LENGTH);
            }

            break;
          }
          case IPV6_ECN: {
            PISA_COWARDLY_VERSION_CHECK(Pliney::IpVersion::SIX,
                                        pisa_pgm_ip_version,
                                        "Will not set an IPv6 ECN value on a "
                                        "non-IPv6 PISA program.");
            int ecn = program->insts[insn_idx].value.value.byte;
            struct ip6_hdr *typed_hdr = (struct ip6_hdr *)iphdr;
            typed_hdr->ip6_flow &= ~(htonl(0x3 << 20));
            typed_hdr->ip6_flow |= htonl(ecn << 20);

            break;
          }
          case IPV4_ECN: {
            PISA_COWARDLY_VERSION_CHECK(Pliney::IpVersion::FOUR,
                                        pisa_pgm_ip_version,
                                        "Will not set an IPv4 ECN value on a "
                                        "non-IPv4 PISA program.");
            int ecn = program->insts[insn_idx].value.value.byte;
            struct iphdr *typed_hdr = (struct iphdr *)iphdr;
            // First, remove the previous ECN value.
            typed_hdr->tos &= 0xfc;
            // Now, set the ECN.
            typed_hdr->tos |= ecn;
            break;
          }
          case IPV6_DSCP: {
            PISA_COWARDLY_VERSION_CHECK(Pliney::IpVersion::SIX,
                                        pisa_pgm_ip_version,
                                        "Will not set an IPv6 DSCP value on a "
                                        "non-IPv6 PISA program.");
            int dscp = program->insts[insn_idx].value.value.byte;
            struct ip6_hdr *typed_hdr = (struct ip6_hdr *)iphdr;
            typed_hdr->ip6_flow &= ~(htonl(0xfc << 20));
            typed_hdr->ip6_flow |= htonl(dscp << 20);

            break;
          }
          case IPV4_DSCP: {
            PISA_COWARDLY_VERSION_CHECK(Pliney::IpVersion::FOUR,
                                        pisa_pgm_ip_version,
                                        "Will not set an IPv4 DSCP value on a "
                                        "non-IPv4 PISA program.");
            int dscp = program->insts[insn_idx].value.value.byte;
            struct iphdr *typed_hdr = (struct iphdr *)iphdr;
            typed_hdr->tos &= 0x3;
            typed_hdr->tos |= dscp;
            break;
          }
          case IPV6_HL: {
            PISA_COWARDLY_VERSION_CHECK(
                Pliney::IpVersion::SIX, pisa_pgm_ip_version,
                "Will not set a hoplimit a non-IPv6 PISA program.");
            int hl = program->insts[insn_idx].value.value.byte;
            struct ip6_hdr *typed_hdr = (struct ip6_hdr *)iphdr;
            typed_hdr->ip6_hlim = hl;
            break;
          }
          case IPV4_TTL: {
            PISA_COWARDLY_VERSION_CHECK(
                Pliney::IpVersion::FOUR, pisa_pgm_ip_version,
                "Will not set a ttl a non-IPv4 PISA program.");
            int ttl = program->insts[insn_idx].value.value.byte;
            struct iphdr *typed_hdr = (struct iphdr *)iphdr;
            typed_hdr->ttl = ttl;
            break;
          }
          default: {
            Logger::ActiveLogger()->log(
                Logger::WARN,
                std::format(
                    "Packet Runner does not yet handle fields of kind {}",
                    pisa_field_name(program->insts[insn_idx].fk.field)));
          }
        };
        break;
      } // SET_FIELD
      default: {
        Logger::ActiveLogger()->log(
            Logger::WARN,
            std::format(
                "Packet Runner does not yet handle operations of kind {}",
                pisa_opcode_name(program->insts[insn_idx].op)));
      }
    }
  }

  if (ip_opts_exts_hdr.opts_exts_count > 0) {

    size_t next_header_offsets[256] = {};
    uint8_t next_header_values[256] = {};
    uint8_t first_next_header{0};
    size_t total_extension_headers{0};

    size_t supported_ipv6_exts_count{};
    auto supported_ipv6_exts{
        supported_exts_ip_opts_exts(&supported_ipv6_exts_count)};
    for (size_t i{0}; i < supported_ipv6_exts_count; i++) {
      auto ext_type = supported_ipv6_exts[i];
      pisa_ip_opt_ext_t coalesced_ext{
          coalesce_ip_opts_exts(ip_opts_exts_hdr, ext_type)};

      if (!coalesced_ext.len) {
        continue;
      }

      size_t full_extension_header_len{};
      uint8_t *full_extension_header{};
      if (!to_raw_ip_opts_exts(coalesced_ext, &full_extension_header_len,
                               &full_extension_header)) {
        // TODO
      }

      // By default, set to transport type (we fixup later!)
      next_header_offsets[total_extension_headers] = ip_opt_ext_hdr_raw_len;
      next_header_values[total_extension_headers] = to_native_transport(pisa_pgm_transport_type);
      if (total_extension_headers == 0) {
        first_next_header = to_native_ext_type_ip_opts_exts(coalesced_ext.oe);
      } else {
        next_header_values[total_extension_headers-1] = to_native_ext_type_ip_opts_exts(coalesced_ext.oe);
      }

      ip_opts_exts_hdr_raw =
          (uint8_t *)realloc(ip_opts_exts_hdr_raw, (ip_opt_ext_hdr_raw_len +
                                                    full_extension_header_len) *
                                                       sizeof(uint8_t));
      memcpy(ip_opts_exts_hdr_raw + ip_opt_ext_hdr_raw_len,
             full_extension_header, full_extension_header_len);

      ip_opt_ext_hdr_raw_len += full_extension_header_len;

      free_ip_opt_ext(coalesced_ext);
      free(full_extension_header);
      total_extension_headers++;
    }

    for (size_t i{0}; i < total_extension_headers; i++) {
      ip_opts_exts_hdr_raw[next_header_offsets[i]] = next_header_values[i];
    }

    if (pisa_pgm_ip_version == Pliney::IpVersion::SIX) {
      struct ip6_hdr *typed_hdr{reinterpret_cast<struct ip6_hdr *>(iphdr)};
      typed_hdr->ip6_nxt = first_next_header;
    }
  }
  free_ip_opts_exts(ip_opts_exts_hdr);

  // If we have a UDP packet (for v6), we _must_ calculate the checksum.
  if (pisa_pgm_transport_type == Pliney::Transport::UDP &&
      pisa_pgm_ip_version == Pliney::IpVersion::SIX) {
    struct udphdr *typed_hdr = (struct udphdr *)transport;

    data_p body{
        .len = pgm_body.value.ptr.len,
        .data = pgm_body.value.ptr.data,
    };
    typed_hdr->check =
        compute_udp_cksum(pisa_pgm_ip_version, iphdr, typed_hdr, body);
  } else if (pisa_pgm_transport_type == Pliney::Transport::ICMP) {
    struct icmphdr *typed_hdr = (struct icmphdr *)transport;
    data_p body{
        .len = pgm_body.value.ptr.len,
        .data = pgm_body.value.ptr.data,
    };
    typed_hdr->checksum = compute_icmp_cksum(typed_hdr, body);
  }

  // Now that we are sure what the contents of the packet hold, we _may_
  // need to update the len!
  if (pisa_pgm_ip_version == Pliney::IpVersion::SIX) {
    struct ip6_hdr *typed_hdr{reinterpret_cast<struct ip6_hdr *>(iphdr)};
    typed_hdr->ip6_plen =
        htons(ntohs(typed_hdr->ip6_plen) + ip_opt_ext_hdr_raw_len +
              transport_len + transportoptionhdr_len);
  } else {
    struct iphdr *typed_hdr{reinterpret_cast<struct iphdr *>(iphdr)};
    typed_hdr->tot_len =
        htons(ntohs(typed_hdr->tot_len) + ip_opt_ext_hdr_raw_len +
              transport_len + transportoptionhdr_len);
  }

  size_t total_len{iphdr_len + ip_opt_ext_hdr_raw_len + transport_len +
                   transportoptionhdr_len + pgm_body.value.ptr.len};
  uint8_t *packet{(uint8_t *)calloc(total_len, sizeof(uint8_t))};

  // Copy the IP header into the consolidated packet.
  memcpy(packet, iphdr, iphdr_len);
  // Copy the ip options header into the consolidated header.
  memcpy(packet + iphdr_len, ip_opts_exts_hdr_raw, ip_opt_ext_hdr_raw_len);
  // Copy the transport into the consolidated header.
  memcpy(packet + iphdr_len + ip_opt_ext_hdr_raw_len, transport, transport_len);
  // Copy the transport options into the consolidated header.
  memcpy(packet + iphdr_len + ip_opt_ext_hdr_raw_len + transport_len,
         transportoptionhdr, transportoptionhdr_len);
  // Copy the body into the consolidated header!
  memcpy(packet + iphdr_len + ip_opt_ext_hdr_raw_len + transport_len +
             transportoptionhdr_len,
         pgm_body.value.ptr.data, pgm_body.value.ptr.len);

  // The entire packet is reachable from .all, but ...
  compilation.packet.all.data = packet;
  compilation.packet.all.len = total_len;

  // ... there are views for different pieces ...
  compilation.packet.ip.data = packet;
  compilation.packet.ip.len = iphdr_len;

  // ... there are views for different pieces ...
  compilation.packet.ip_opts_exts.data = packet + iphdr_len;
  compilation.packet.ip_opts_exts.len = ip_opt_ext_hdr_raw_len;

  // ... and ...
  compilation.packet.transport.data =
      packet + iphdr_len + ip_opt_ext_hdr_raw_len;
  compilation.packet.transport.len = transport_len;

  compilation.packet.transport_options.data =
      packet + iphdr_len + ip_opt_ext_hdr_raw_len + transport_len;
  compilation.packet.transport_options.len = transportoptionhdr_len;

  // ... and one more!
  compilation.packet.body.data = packet + iphdr_len + ip_opt_ext_hdr_raw_len +
                                 transport_len + transportoptionhdr_len;
  compilation.packet.body.len = pgm_body.value.ptr.len;

  // Free what we allocated locally.
  free(iphdr);
  // TODO
  free(ip_opts_exts_hdr_raw);
  free(transport);
  free(transportoptionhdr);

  return true;
}

bool PacketObserverRunner::execute(Compilation &compilation) {
  if (!PacketRunner::execute(compilation)) {
    return false;
  }

  for (auto invocation : *compilation.pipeline) {
    invocation.plugin.observe(compilation.program.get(), &compilation.packet,
                              invocation.cookie);
  }

  return true;
}

bool PacketSenderRunner::execute(Compilation &compilation) {
  if (!PacketObserverRunner::execute(compilation)) {
    return false;
  }

  // Find out the target and transport.
  struct iphdr *iphdr = (struct iphdr *)compilation.packet.ip.data;
  struct sockaddr_storage saddrs{};
  size_t saddrs_len{0};
  if (iphdr->version == 0x4) {
    struct sockaddr_in *saddri{reinterpret_cast<struct sockaddr_in *>(&saddrs)};
    saddri->sin_addr.s_addr = iphdr->daddr;
    saddri->sin_family = AF_INET;
    saddrs_len = sizeof(struct sockaddr_in);
  } else {
    struct ip6_hdr *iphdr = (struct ip6_hdr *)compilation.packet.ip.data;
    struct sockaddr_in6 *saddri{
        reinterpret_cast<struct sockaddr_in6 *>(&saddrs)};
    saddri->sin6_addr = iphdr->ip6_dst;
    saddri->sin6_family = AF_INET6;
    saddrs_len = sizeof(struct sockaddr_in6);
  }

  int send_socket{socket(iphdr->version == 0x4 ? AF_INET : AF_INET6, SOCK_RAW,
                         IPPROTO_RAW)};

  if (send_socket < 0) {
    Logger::ActiveLogger()->log(
        Logger::ERROR,
        std::format("Could not open a raw socket: {}", strerror(errno)));
    return false;
  }

  if (sendto(send_socket, compilation.packet.all.data,
             compilation.packet.all.len, 0, (struct sockaddr *)&saddrs,
             saddrs_len) < 0) {
    Logger::ActiveLogger()->log(
        Logger::ERROR,
        std::format("Could not send constructed packet: {}", strerror(errno)));
    return false;
  }

  return true;
}

bool SocketBuilderRunner::execute_set_field(
    Compilation &compilation, pisa_inst_t instruction,
    pisa_value_t &pisa_pgm_body, std::optional<ip_addr_t> &maybe_pgm_source,
    ip_addr_t pliney_destination) {

  switch (instruction.fk.field) {
    default: {
      Logger::ActiveLogger()->log(
          Logger::WARN,
          std::format(
              "Socket Builder Runner does not handle setting the field {}",
              pisa_field_name(instruction.fk.field)));
      break;
    }
    case IPV4_TARGET_PORT:
    case IPV6_TARGET_PORT:
    case IPV4_TARGET:
    case IPV6_TARGET: {
      break;
    }
    case IPV4_SOURCE: {
      PISA_COWARDLY_VERSION_CHECK(
          PLINEY_IPVERSION4, pliney_destination.family,
          "Will not set the IPv4 source on a non-IPv4 packet");

      auto addr = instruction.value.value.ipaddr.addr;
      auto family = instruction.value.value.ipaddr.family;

      maybe_pgm_source =
          maybe_pgm_source
              .or_else([]() { return std::optional<ip_addr_t>{ip_addr_t{}}; })
              .transform([&addr, &family](auto existing) {
                existing.addr = addr;
                existing.family = family;
                return existing;
              });
      break;
    }
    case IPV4_SOURCE_PORT: {
      PISA_COWARDLY_VERSION_CHECK(
          PLINEY_IPVERSION4, pliney_destination.family,
          "Will not set the IPv4 source port on a non-IPv4 packet");
      auto port = instruction.value.value.ipaddr.port;

      maybe_pgm_source =
          maybe_pgm_source
              .or_else([]() { return std::optional<ip_addr_t>{ip_addr_t{}}; })
              .transform([&port](auto existing) {
                existing.port = port;
                return existing;
              });
      break;
    }
    case IPV6_SOURCE: {
      PISA_COWARDLY_VERSION_CHECK(
          PLINEY_IPVERSION6, pliney_destination.family,
          "Will not set the IPv6 source on a non-IPv6 packet");

      auto addr = instruction.value.value.ipaddr.addr;
      auto family = instruction.value.value.ipaddr.family;

      maybe_pgm_source =
          maybe_pgm_source
              .or_else([]() { return std::optional<ip_addr_t>{ip_addr_t{}}; })
              .transform([&addr, &family](auto existing) {
                existing.addr = addr;
                existing.family = family;
                return existing;
              });
      break;
    }
    case IPV6_SOURCE_PORT: {
      PISA_COWARDLY_VERSION_CHECK(
          PLINEY_IPVERSION6, pliney_destination.family,
          "Will not set the IPv6 source port on a non-IPv6 packet");
      auto port = instruction.value.value.ipaddr.port;

      maybe_pgm_source =
          maybe_pgm_source
              .or_else([]() { return std::optional<ip_addr_t>{ip_addr_t{}}; })
              .transform([&port](auto existing) {
                existing.port = port;
                return existing;
              });
      break;
    }
    case APPLICATION_BODY: {
      if (instruction.value.tpe != PTR) {
        std::string error = "Will not set a body from a non-pointer value.";
        Logger::ActiveLogger()->log(Logger::ERROR, error);
        compilation.error = error;
        return false;
      };
      pisa_pgm_body = instruction.value;
      break;
    }
    case IPV6_ECN:
    case IPV4_ECN: {
      int ecn = instruction.value.value.byte;

      uint8_t set_type = instruction.fk.field == IPV6_ECN ? PLINEY_IPVERSION6
                                                          : PLINEY_IPVERSION4;
      if (pliney_destination.family != set_type) {
        // Better error message.
        Logger::ActiveLogger()->log(
            Logger::WARN, std::format("Will not set ECN value on socket "
                                      "with mismatched IP version"));
        break;
      }
      if (m_toss) {
        (*m_toss).again(ecn, 0x3);
      } else {
        if (pliney_destination.family == PLINEY_IPVERSION6) {
          m_toss.emplace(m_socket, IPPROTO_IPV6, IPV6_TCLASS, ecn, 0x3);
        } else {
          m_toss.emplace(m_socket, IPPROTO_IP, IP_TOS, ecn, 0x3);
        }
      }
      if (!m_toss->ok()) {
        std::string error{std::format(
            "There was an error setting the ECN on the socket: {}\n",
            std::strerror(errno))};
        Logger::ActiveLogger()->log(Logger::ERROR, error);
        compilation.error = error;
        return false;
      }
      break;
    }
    case IPV6_DSCP:
    case IPV4_DSCP: {
      int dscp = instruction.value.value.byte;

      uint8_t set_type = instruction.fk.field == IPV6_DSCP ? PLINEY_IPVERSION6
                                                           : PLINEY_IPVERSION4;
      if (pliney_destination.family != set_type) {
        // Better error message.
        Logger::ActiveLogger()->log(
            Logger::WARN, std::format("Will not set DSCP value on socket "
                                      "with mismatched IP version"));
        break;
      }
      if (m_toss) {
        (*m_toss).again(dscp, 0xfc);
      } else {
        if (pliney_destination.family == PLINEY_IPVERSION6) {
          m_toss.emplace(m_socket, IPPROTO_IPV6, IPV6_TCLASS, dscp, 0xfc);
        } else {
          m_toss.emplace(m_socket, IPPROTO_IP, IP_TOS, dscp, 0xfc);
        }
      }
      if (!m_toss->ok()) {
        std::string error{std::format(
            "There was an error setting the DSCP on the socket: {}\n",
            std::strerror(errno))};
        Logger::ActiveLogger()->log(Logger::ERROR, error);
        compilation.error = error;
        return false;
      }
      break;
    }

    case IPV6_HL: {
      int hoplimit = instruction.value.value.byte;
      PISA_COWARDLY_VERSION_CHECK(
          PLINEY_IPVERSION6, pliney_destination.family,
          "Will not set the IPv6 hoplimit on a non-IPv6 packet");

      m_ttlhl.emplace(m_socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, hoplimit);
      if (!m_ttlhl->ok()) {
        std::cerr << std::format("There was an error setting the "
                                 "hoplimit on the socket: {}\n",
                                 std::strerror(errno));
        return false;
      }
      break;
    }
    case IPV4_TTL: {
      int ttl = instruction.value.value.byte;
      PISA_COWARDLY_VERSION_CHECK(
          PLINEY_IPVERSION4, pliney_destination.family,
          "Will not set the IPv4 TTL on a non-IPv4 packet");

      m_ttlhl.emplace(m_socket, IPPROTO_IP, IP_TTL, ttl);
      if (!m_ttlhl->ok()) {
        std::string error{std::format(
            "There was an error setting the TTL on the socket: {}\n",
            std::strerror(errno))};
        Logger::ActiveLogger()->log(Logger::ERROR, error);
        compilation.error = error;
        return false;
      }
      break;
    }
  }

  return true;
}

bool SocketBuilderRunner::execute(Compilation &compilation) {
  if (!compilation) {
    return false;
  }

  auto &program = compilation.program;

  // As part of our work, we also run another runner that lets
  // each of the plugins in the pipeline see the packet that was
  // built.
  auto packet_observer_runner = PacketObserverRunner();
  auto packet_observer_runner_result =
      packet_observer_runner.execute(compilation);
  if (!packet_observer_runner_result) {
    Logger::ActiveLogger()->log(
        Logger::DEBUG,
        "Error occurred running the packet observer on the PISA program.\n");
  }

  pisa_value_t pgm_body{};

  ip_addr_t pisa_target_address{};
  std::optional<ip_addr_t> maybe_pgm_source;
  Pliney::Transport pisa_pgm_transport_type{};

  if (!find_program_target_transport(program, pisa_target_address,
                                     pisa_pgm_transport_type)) {
    compilation.error =
        "Could not find the target and/or transport in the PISA program";
    return false;
  }

  struct sockaddr *destination = nullptr;
  int destination_len = ip_to_sockaddr(pisa_target_address, &destination);
  if (destination_len < 0) {
    std::string error{
        "Error occurred converting the target address generated by "
        "the PISA program into a system-compatible address."};
    Logger::ActiveLogger()->log(Logger::ERROR, error);
    compilation.error = error;
    compilation.success = false;
    return false;
  }
  m_destination =
      unique_sockaddr((struct sockaddr *)destination, destination_len);
  m_destination_len = destination_len;

  // Only the TCP and UDP transports are valid for this runner.
  if (pisa_pgm_transport_type != Pliney::Transport::TCP &&
      pisa_pgm_transport_type != Pliney::Transport::UDP) {
    auto error{std::format("Invalid transport type ({}); only TCP and UDP are "
                           "allowed for the Socket Builder Runner.",
                           to_string(pisa_pgm_transport_type))};
    Logger::ActiveLogger()->log(Logger::ERROR, error);
    compilation.error = error;
    compilation.success = false;
    return false;
  }

  // Now, open a socket!
  auto socket_success =
      ip_to_socket(pisa_target_address,
                   to_pisa_transport(pisa_pgm_transport_type), &m_socket);
  if (!socket_success || m_socket < 0) {
    std::string reason{"Ill-formatted target"};
    if (socket_success) {
      reason = strerror(errno);
    }
    auto error =
        std::format("Could not open a {} socket to the target address ({}): "
                    "{}.",
                    to_string(pisa_pgm_transport_type),
                    stringify_ip(pisa_target_address), reason);
    Logger::ActiveLogger()->log(Logger::ERROR, error);
    compilation.error = error;
    return false;
  }

  for (size_t insn_idx{0}; insn_idx < program->inst_count; insn_idx++) {
    switch (program->insts[insn_idx].op) {
      case EXEC:
      case SET_META: {
        // During execution, EXEC, and SET_META operations are noops.
        break;
      } // EXEC, SET_META
      case ADD_IP_OPT_EXT: {
        if (program->insts[insn_idx].value.tpe == IP_EXT) {
          auto ip_ext{program->insts[insn_idx].value.value.ext};
          add_ip_opt_ext(&m_ip_opts_exts_hdr, ip_ext);
        } else {
          Logger::ActiveLogger()->log(
              Logger::ERROR, std::format("IP Options are not yet supported"));
        }
        break;
      } // ADD_IP_OPT_EXT
      case SET_FIELD: {
        if (!execute_set_field(compilation, program->insts[insn_idx], pgm_body,
                               maybe_pgm_source, pisa_target_address)) {
          return false;
        }
        break;
      } // SET_FIELD
      default: {
        Logger::ActiveLogger()->log(
            Logger::ERROR,
            std::format("Socket Builder Runner does not handle {} operations",
                        pisa_opcode_name(program->insts[insn_idx].op)));
      } // default
    }
  }

  if (maybe_pgm_source) {
    struct sockaddr *source_saddr{nullptr};
    auto saddr_size{ip_to_sockaddr(*maybe_pgm_source, &source_saddr)};
    if (bind(m_socket, source_saddr, saddr_size) < 0) {
      auto error = std::format("Failed to bind to the source address: {}",
                               strerror(errno));
      Logger::ActiveLogger()->log(Logger::ERROR, error);
      compilation.error = error;
      return false;
    };
  }

  if (m_ip_opts_exts_hdr.opts_exts_count > 0) {
    size_t supported_ipv6_exts_count{};
    auto supported_ipv6_exts{
        supported_exts_ip_opts_exts(&supported_ipv6_exts_count)};
    for (size_t i{0}; i < supported_ipv6_exts_count; i++) {
      auto ext_type = supported_ipv6_exts[i];
      pisa_ip_opt_ext_t coalesced_ext{
          coalesce_ip_opts_exts(m_ip_opts_exts_hdr, ext_type)};

      if (!coalesced_ext.len) {
        continue;
      }

      size_t full_extension_header_len{};
      uint8_t *full_extension_header{};

      if (!to_raw_ip_opts_exts(coalesced_ext, &full_extension_header_len,
                               &full_extension_header)) {
        auto error =
            std::format("Could not convert the PISA program-generated IP "
                        "options into their wire format.");
        Logger::ActiveLogger()->log(Logger::ERROR, error);
        compilation.error = error;
        return false;
      }

      auto result =
          setsockopt(m_socket, IPPROTO_IPV6, ext_type, full_extension_header,
                     full_extension_header_len);
      if (result < 0) {
        Logger::ActiveLogger()->log(
            Logger::ERROR,
            std::format("Error occurred setting an extension option: {}",
                        strerror(errno)));
        return false;
      }
      free_ip_opt_ext(coalesced_ext);
      free(full_extension_header);
    }
  }
  free_ip_opts_exts(m_ip_opts_exts_hdr);
  return true;
}

bool CliRunner::execute(Compilation &compilation) {
  if (!compilation) {
    return false;
  }
  SocketBuilderRunner::execute(compilation);
  if (!compilation) {
    return false;
  }

  if (connect(m_socket, m_destination->get(), m_destination_len) < 0) {
    compilation.error = "Could not connect the socket.";
    Logger::ActiveLogger()->log(Logger::ERROR, "Could not connect the socket.");
    return false;
  }

  int write_result = sendto(m_socket, compilation.packet.body.data,
                            compilation.packet.body.len, 0,
                            m_destination->get(), m_destination_len);

  if (write_result < 0) {
    auto error_msg = std::format("Error occurred sending data: could not "
                                 "write to the socket: {}",
                                 strerror(errno));

    Logger::ActiveLogger()->log(Logger::ERROR, error_msg);
    compilation.error = error_msg;
    return false;
  }

  return true;
}

bool XdpRunner::execute(Compilation &compilation) {

  if (!compilation) {
    return false;
  }

  auto &program = compilation.program;

  pisa_value_t pisa_xdp_output_file{.tpe = PTR};

  // Now, find out the transport type. The program must set one.
  if (!pisa_program_find_meta_value(program.get(), "XDP_OUTPUT_FILE",
                                    &pisa_xdp_output_file)) {
    auto error_msg{"Could not find the name of the XDP output file!"};
    Logger::ActiveLogger()->log(Logger::ERROR, error_msg);
    compilation.error = error_msg;
    return false;
  }

  auto xdp_path = std::filesystem::path("./skel/xdp.c");
  auto xdp_output_path =
      std::filesystem::path((char *)pisa_xdp_output_file.value.ptr.data);

  std::ifstream xdp_skel{xdp_path};

  if (!xdp_skel) {
    return false;
  }

  std::ofstream xdp_output_skel{xdp_output_path, std::ios::trunc};
  if (!xdp_output_skel) {
    return false;
  }

  // Read the entire skeleton file.
  std::string xdp_skel_contents{};
  char xdp_skel_just_read{};
  xdp_skel >> std::noskipws;
  while (xdp_skel >> xdp_skel_just_read) {
    xdp_skel_contents += xdp_skel_just_read;
  }

  std::string xdp_ipv4_code{};
  std::string xdp_ipv6_code{};

  for (size_t insn_idx{0}; insn_idx < program->inst_count; insn_idx++) {
    switch (program->insts[insn_idx].op) {
      case SET_META: {
        Logger::ActiveLogger()->log(
            Logger::DEBUG,
            std::format("SET_META is a no-op for Packet Runner."));
        break;
      } // SET_META
      case SET_FIELD: {
        switch (program->insts[insn_idx].fk.field) {
          case IPV6_HL: {
            int hl = program->insts[insn_idx].value.value.byte;
            xdp_ipv6_code += std::format("ipv6->ip6_hlim = {};\n", hl);
            break;
          }
          case IPV4_TTL: {
            int ttl = program->insts[insn_idx].value.value.byte;
            xdp_ipv4_code += std::format("ip->ttl = {};\n", ttl);
            break;
          }
          case IPV4_ECN: {
            int ecn = program->insts[insn_idx].value.value.byte;
            // First, remove the previous ECN value.
            xdp_ipv4_code += std::format("ip->tos &= 0xfc;\n");
            xdp_ipv4_code += std::format("ip->tos |= {};\n", ecn);
            break;
          }
          case APPLICATION_BODY:
          case IPV6_ECN:
          case IPV6_DSCP:
          case IPV4_DSCP:
          case IPV6_TARGET:
          case IPV4_TARGET:
          default: {
            Logger::ActiveLogger()->log(
                Logger::WARN,
                std::format(
                    "Packet Runner does not yet handle operations of kind {}",
                    pisa_opcode_name(program->insts[insn_idx].op)));
          }

        }; // SET_FIELD
        break;
        default: {
          Logger::ActiveLogger()->log(
              Logger::WARN,
              std::format(
                  "Packet Runner does not yet handle operations of kind {}",
                  pisa_opcode_name(program->insts[insn_idx].op)));
        }
      }
    }
  }

  // Emit the xdp source code.
  std::regex skel_ip_regex{"//__IPV4_PLINEY"};
  std::regex skel_ipv6_regex{"//__IPV6_PLINEY"};
  xdp_skel_contents =
      std::regex_replace(xdp_skel_contents, skel_ip_regex, xdp_ipv4_code);
  xdp_skel_contents =
      std::regex_replace(xdp_skel_contents, skel_ipv6_regex, xdp_ipv6_code);
  xdp_output_skel << xdp_skel_contents;

  return true;
}

bool ForkRunner::execute(Compilation &compilation) {
  if (!compilation) {
    return false;
  }

  auto &program = compilation.program;

  SocketBuilderRunner::execute(compilation);
  if (!compilation) {
    return false;
  }

  if (connect(m_socket, m_destination->get(), m_destination_len) < 0) {
    compilation.error = "Could not connect the socket.";
    Logger::ActiveLogger()->log(Logger::ERROR, "Could not connect the socket.");
    return false;
  }

  // For as many exec instructions as there are in the PISA program, do the
  // bidding!
  pisa_inst_t *pisa_exec_inst{nullptr};
  size_t last_pisa_exec_inst{0};
  while (pisa_program_find_inst(program.get(), &last_pisa_exec_inst,
                                &pisa_exec_inst, EXEC)) {
    pisa_callback_t exec_func{
        (pisa_callback_t)(pisa_exec_inst->value.value.callback.callback)};
    exec_func(m_socket, pisa_exec_inst->value.value.callback.cookie);
    last_pisa_exec_inst += 1;
  }
  return true;
}
