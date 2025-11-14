#include "packetline/runner.hpp"
#include "lib/ip.hpp"
#include "packetline/constants.hpp"

#include "lib/logger.hpp"
#include "packetline/utilities.hpp"
#include "pisa/pisa.h"
#include "pisa/plugin.h"
#include "pisa/utils.h"

#include <cstdint>
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

bool PacketRunner::execute(Compilation &compilation) {

  if (!compilation) {
    return false;
  }

  auto &program = compilation.program;

  pisa_value_t pgm_body{};
  pisa_value_t pgm_dest{};
  pisa_value_t pisa_transport_value = {.tpe = BYTE};

  // First, find the target of the packet. The program must set one.
  if (!pisa_program_find_target_value(program.get(), &pgm_dest)) {
    Logger::ActiveLogger()->log(Logger::ERROR,
                                "Could not find the target value!");
    compilation.error = "PISA program does not contain a target value.";
    return false;
  }

  // Now, find out the transport type. The program must set one.
  if (!pisa_program_find_meta_value(program.get(), "TRANSPORT",
                                    &pisa_transport_value)) {
    Logger::ActiveLogger()->log(Logger::ERROR,
                                "Could not find the transport value!");
    compilation.error = "PISA program does not contain a transport value.";
    return false;
  }

  auto pisa_pgm_transport_type{
      Pliney::from_pisa_transport(pisa_transport_value.value.byte)};
  auto pisa_pgm_ip_version{
      Pliney::from_pisa_version(pgm_dest.value.ipaddr.family)};

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
  size_t ipoptionhdr_len{0};
  uint8_t *ipoptionhdr{nullptr};

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
              typed_hdr->tot_len = htons((typed_hdr->ihl * 4) + transport_len +
                                         pgm_body.value.ptr.len);
            } else {
              struct ip6_hdr *typed_hdr = (struct ip6_hdr *)iphdr;
              typed_hdr->ip6_plen =
                  htons(transport_len + pgm_body.value.ptr.len);
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

  size_t total_len{iphdr_len + ipoptionhdr_len + transport_len +
                   transportoptionhdr_len + pgm_body.value.ptr.len};
  uint8_t *packet{(uint8_t *)calloc(total_len, sizeof(uint8_t))};

  // Copy the IP header into the consolidated packet.
  memcpy(packet, iphdr, iphdr_len);
  // Copy the ip options header into the consolidated header.
  memcpy(packet + iphdr_len, ipoptionhdr, ipoptionhdr_len);
  // Copy the transport into the consolidated header.
  memcpy(packet + iphdr_len + ipoptionhdr_len, transport, transport_len);
  // Copy the transport options into the consolidated header.
  memcpy(packet + iphdr_len + ipoptionhdr_len + transport_len,
         transportoptionhdr, transportoptionhdr_len);
  // Copy the body into the consolidated header!
  memcpy(packet + iphdr_len + ipoptionhdr_len + transport_len +
             transportoptionhdr_len,
         pgm_body.value.ptr.data, pgm_body.value.ptr.len);

  // The entire packet is reachable from .all, but ...
  compilation.packet.all.data = packet;
  compilation.packet.all.len = total_len;

  // ... there are views for different pieces ...
  compilation.packet.ip.data = packet;
  compilation.packet.ip.len = iphdr_len;

  // ... there are views for different pieces ...
  compilation.packet.ip_options.data = ipoptionhdr;
  compilation.packet.ip_options.len = ipoptionhdr_len;

  // ... and ...
  compilation.packet.transport.data = packet + iphdr_len + ipoptionhdr_len;
  compilation.packet.transport.len = transport_len;

  compilation.packet.transport_options.data =
      packet + iphdr_len + ipoptionhdr_len + transport_len;
  compilation.packet.transport_options.len = transportoptionhdr_len;

  // ... and one more!
  compilation.packet.body.data = packet + iphdr_len + ipoptionhdr_len +
                                 transport_len + transportoptionhdr_len;
  compilation.packet.body.len = pgm_body.value.ptr.len;

  // Free what we allocated locally.
  free(iphdr);
  free(ipoptionhdr);
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
  if (!PacketRunner::execute(compilation)) {
    return false;
  }

  // Find out the target and transport.
  struct iphdr *iphdr = (struct iphdr *)compilation.packet.ip.data;
  struct sockaddr_storage saddrs {};
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
  pisa_value_t pgm_dest;
  std::optional<pisa_value_t> maybe_pgm_source;
  pisa_value_t pisa_transport_value = {.tpe = BYTE};

  // First, find the destination. The program must set one.
  if (!pisa_program_find_target_value(program.get(), &pgm_dest)) {
    Logger::ActiveLogger()->log(Logger::ERROR,
                                "Could not find the target value!");
    compilation.success = false;
    return false;
  }
  auto pliney_destination = pgm_dest.value.ipaddr;
  struct sockaddr *destination = nullptr;
  int destination_len = ip_to_sockaddr(pgm_dest.value.ipaddr, &destination);
  if (destination_len < 0) {
    std::cerr << "Error occurred converting generated destination into "
                 "system-compatible destination.\n";
    compilation.success = false;
    return false;
  }
  m_destination =
      unique_sockaddr((struct sockaddr *)destination, destination_len);
  m_destination_len = destination_len;

  // Now, find out the transport type. The program must set one.
  if (!pisa_program_find_meta_value(program.get(), "TRANSPORT",
                                    &pisa_transport_value)) {
    Logger::ActiveLogger()->log(Logger::ERROR,
                                "Could not find the transport value!");
    compilation.success = false;
    return false;
  }
  auto pisa_pgm_transport_type{
      Pliney::from_pisa_transport(pisa_transport_value.value.byte)};

  // Only the TCP and UDP transports are valid for this runner.
  if (pisa_pgm_transport_type != Pliney::Transport::TCP &&
      pisa_pgm_transport_type != Pliney::Transport::UDP) {
    auto error{std::format("Invalid transport type ({}); only TCP and UDP are "
                           "allowed for this runner.",
                           to_string(pisa_pgm_transport_type))};
    Logger::ActiveLogger()->log(Logger::ERROR, error);
    compilation.error = error;
    compilation.success = false;
    return false;
  }

  // Now, open a socket!
  auto socket_success =
      ip_to_socket(pliney_destination,
                   to_pisa_transport(pisa_pgm_transport_type), &m_socket);
  if (!socket_success || m_socket < 0) {
    std::string reason{"Ill-formatted target"};
    if (socket_success) {
      reason = strerror(errno);
    }
    Logger::ActiveLogger()->log(
        Logger::ERROR,
        std::format("Could not open a {} socket to the target address ({}): "
                    "{}.",
                    to_string(pisa_pgm_transport_type),
                    stringify_ip(pgm_dest.value.ipaddr), reason));
    return false;
  }

  for (size_t insn_idx{0}; insn_idx < program->inst_count; insn_idx++) {
    switch (program->insts[insn_idx].op) {
      case SET_META: {
        // During execution, SET_META operations are noops.
        break;
      }
      case SET_FIELD: {
        switch (program->insts[insn_idx].fk.field) {
          case IPV4_TARGET: {
            // A noop.
            break;
          }
          case IPV6_TARGET: {
            // A noop.
            break;
          }
          case IPV4_SOURCE: {
            PISA_COWARDLY_VERSION_CHECK(
                PLINEY_IPVERSION4, pliney_destination.family,
                "Will not set the IPv4 source on a non-IPv4 packet");

            auto addr = program->insts[insn_idx].value.value.ipaddr.addr;
            auto family = program->insts[insn_idx].value.value.ipaddr.family;

            maybe_pgm_source =
                maybe_pgm_source
                    .or_else([]() {
                      return std::optional<pisa_value_t>{pisa_value_t{}};
                    })
                    .transform([&addr, &family](auto existing) {
                      existing.value.ipaddr.addr = addr;
                      existing.value.ipaddr.family = family;
                      return existing;
                    });
            break;
          }
          case IPV4_SOURCE_PORT: {
            PISA_COWARDLY_VERSION_CHECK(
                PLINEY_IPVERSION4, pliney_destination.family,
                "Will not set the IPv4 source port on a non-IPv4 packet");
            auto port = program->insts[insn_idx].value.value.ipaddr.port;

            maybe_pgm_source =
                maybe_pgm_source
                    .or_else([]() {
                      return std::optional<pisa_value_t>{pisa_value_t{}};
                    })
                    .transform([&port](auto existing) {
                      existing.value.ipaddr.port = port;
                      return existing;
                    });
            break;
          }
          case IPV6_SOURCE: {
            PISA_COWARDLY_VERSION_CHECK(
                PLINEY_IPVERSION6, pliney_destination.family,
                "Will not set the IPv6 source on a non-IPv6 packet");

            auto addr = program->insts[insn_idx].value.value.ipaddr.addr;
            auto family = program->insts[insn_idx].value.value.ipaddr.family;

            maybe_pgm_source =
                maybe_pgm_source
                    .or_else([]() {
                      return std::optional<pisa_value_t>{pisa_value_t{}};
                    })
                    .transform([&addr, &family](auto existing) {
                      existing.value.ipaddr.addr = addr;
                      existing.value.ipaddr.family = family;
                      return existing;
                    });
            break;
          }
          case IPV6_SOURCE_PORT: {
            PISA_COWARDLY_VERSION_CHECK(
                PLINEY_IPVERSION6, pliney_destination.family,
                "Will not set the IPv6 source port on a non-IPv6 packet");
            auto port = program->insts[insn_idx].value.value.ipaddr.port;

            maybe_pgm_source =
                maybe_pgm_source
                    .or_else([]() {
                      return std::optional<pisa_value_t>{pisa_value_t{}};
                    })
                    .transform([&port](auto existing) {
                      existing.value.ipaddr.port = port;
                      return existing;
                    });
            break;
          }
          case APPLICATION_BODY: {
            if (program->insts[insn_idx].value.tpe != PTR) {
              Logger::ActiveLogger()->log(
                  Logger::WARN,
                  std::format("Will not set a body from a non-pointer value."));
              return false;
            };
            pgm_body = program->insts[insn_idx].value;
            break;
          }
          case IPV6_ECN:
          case IPV4_ECN: {
            int ecn = program->insts[insn_idx].value.value.byte;

            uint8_t set_type = program->insts[insn_idx].fk.field == IPV6_ECN
                                   ? PLINEY_IPVERSION6
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
              std::cerr << std::format(
                  "There was an error setting the ECN on the socket: {}\n",
                  std::strerror(errno));
              return false;
            }
            break;
          }
          case IPV6_DSCP:
          case IPV4_DSCP: {
            int dscp = program->insts[insn_idx].value.value.byte;

            uint8_t set_type = program->insts[insn_idx].fk.field == IPV6_DSCP
                                   ? PLINEY_IPVERSION6
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
              std::cerr << std::format(
                  "There was an error setting the DSCP on the socket: {}\n",
                  std::strerror(errno));
              return false;
            }
            break;
          }

          case IPV6_HL: {
            int hoplimit = program->insts[insn_idx].value.value.byte;
            PISA_COWARDLY_VERSION_CHECK(
                PLINEY_IPVERSION6, pliney_destination.family,
                "Will not set the IPv6 hoplimit on a non-IPv6 packet");

            m_ttlhl.emplace(m_socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                            hoplimit);
            if (!m_ttlhl->ok()) {
              std::cerr << std::format("There was an error setting the "
                                       "hoplimit on the socket: {}\n",
                                       std::strerror(errno));
              return false;
            }
            break;
          }
          case IPV4_TTL: {
            int ttl = program->insts[insn_idx].value.value.byte;
            PISA_COWARDLY_VERSION_CHECK(
                PLINEY_IPVERSION4, pliney_destination.family,
                "Will not set the IPv4 TTL on a non-IPv4 packet");

            m_ttlhl.emplace(m_socket, IPPROTO_IP, IP_TTL, ttl);
            if (!m_ttlhl->ok()) {
              std::cerr << std::format(
                  "There was an error setting the TTL on the socket: {}\n",
                  std::strerror(errno));
              return false;
            }
            break;
          }
        }
        break;
      }
      default: {
        Logger::ActiveLogger()->log(
            Logger::ERROR,
            std::format("Cli Runner does not yet handle operations of kind {}",
                        (int)program->insts[insn_idx].op));
      }
    }
  }

  if (maybe_pgm_source) {
    struct sockaddr *source_saddr{nullptr};
    auto saddr_size{
        ip_to_sockaddr(maybe_pgm_source->value.ipaddr, &source_saddr)};
    if (bind(m_socket, source_saddr, saddr_size) < 0) {
      Logger::ActiveLogger()->log(
          Logger::WARN, std::format("Failed to bind to the source address: {}",
                                    strerror(errno)));
      return false;
    };
  }

#if 0
  // Now, do I have to connect?
  std::optional<Swapsockopt<int>> toss{};
  int tos = (packet.header.diffserv << 2) | packet.header.cong;

  if (tos != 0) {
    if (packet.target.family == PLINEY_IPVERSION6) {
      toss.emplace(socket, IPPROTO_IPV6, IPV6_TCLASS, tos);
    } else {
      toss.emplace(socket, IPPROTO_IP, IP_TOS, tos);
    }
    if (!toss->ok()) {
      std::cerr << std::format(
          "There was an error setting the TOS on the socket: {}\n",
          std::strerror(errno));
      return false;
    }
  }

  Logger::ActiveLogger()->log(Logger::DEBUG,
                              std::format("Trying to send a packet to {}.",
                                          stringify_ip(packet.target)));

  if (packet.transport == INET_STREAM) {
    auto connect_result = connect(socket, destination, destination_len);
    if (connect_result < 0) {
      Logger::ActiveLogger()->log(
          Logger::ERROR, std::format("Error occurred sending data: could not "
                                     "connect the socket: {}",
                                     strerror(errno)));
      return false;
    }
    if (write(socket, packet.body.data, packet.body.len) < 0) {
      Logger::ActiveLogger()->log(
          Logger::ERROR, std::format("Error occurred sending data: could not "
                                     "write the body of the packet: {}",
                                     strerror(errno)));
    };
  } else if (packet.transport == INET_DGRAM) {

    struct msghdr msg {};
    struct iovec iov {};

    memset(&msg, 0, sizeof(struct msghdr));
    iov.iov_base = packet.body.data;
    iov.iov_len = packet.body.len;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    msg.msg_name = destination;
    msg.msg_namelen = destination_len;

    msg.msg_control = nullptr;
    msg.msg_controllen = 0;

    extensions_p header_extensions{.extensions_count = 0,
                                   .extensions_values = nullptr};
    if (packet.target.family == PLINEY_IPVERSION6) {
      header_extensions = copy_extensions(packet.header_extensions);
      if (!coalesce_extensions(&header_extensions, IPV6_HOPOPTS)) {
        Logger::ActiveLogger()->log(
            Logger::ERROR, "Error occurred coalescing hop-by-hop options.");
        return false;
      }
      if (header_extensions.extensions_count > 0) {
        for (auto extension_i{0};
             extension_i < header_extensions.extensions_count; extension_i++) {

          auto extension_header_len =
              ((2 /* for extension header T/L */ +
                header_extensions.extensions_values[extension_i]->len +
                (8 - 1)) /
               8) *
              8;
          Logger::ActiveLogger()->log(
              Logger::DEBUG,
              std::format("extension_header_len: {}", extension_header_len));

          extend_cmsg(&msg, extension_header_len);

          struct cmsghdr *hdr = CMSG_FIRSTHDR(&msg);
          hdr->cmsg_level = SOL_IPV6;
          hdr->cmsg_type =
              header_extensions.extensions_values[extension_i]->type;
          CMSG_DATA(hdr)[0] = 0; // Next header
          CMSG_DATA(hdr)[1] = (extension_header_len / 8) - 1;

          // HbH Extension Header Data.
          memcpy(CMSG_DATA(hdr) + 2,
                 header_extensions.extensions_values[extension_i]->data,
                 header_extensions.extensions_values[extension_i]->len);
        }
      }
    }

    int write_result = sendmsg(socket, &msg, 0);

    free_extensions(header_extensions);

    if (msg.msg_controllen > 0) {
      free(msg.msg_control);
    }
#endif

#if 0
  } else {
    Logger::ActiveLogger()->log(
        Logger::ERROR,
        std::format("Error occurred sending data: the destination address "
                    "had an invalid stream type.",
                    strerror(errno)));
  }
#endif
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

  struct msghdr msg {};
  struct iovec iov {};

  memset(&msg, 0, sizeof(struct msghdr));
  iov.iov_base = nullptr;
  iov.iov_len = 0;

  if (compilation.packet.body.len) {
    iov.iov_base = compilation.packet.body.data;
    iov.iov_len = compilation.packet.body.len;
  }

  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  msg.msg_name = m_destination->get();
  msg.msg_namelen = m_destination_len;

  msg.msg_control = nullptr;
  msg.msg_controllen = 0;

  int write_result = sendmsg(m_socket, &msg, 0);

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
