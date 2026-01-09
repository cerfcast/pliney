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

#include <algorithm>
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
#include <optional>
#include <sys/socket.h>
#include <sys/types.h>

#include <iostream>
#include <variant>

#define PISA_COWARDLY_VERSION_CHECK(expected, actual, message)                 \
  if (actual != expected) {                                                    \
    Logger::ActiveLogger().log(Logger::WARN, std::format(message));            \
    break;                                                                     \
  }

#define PISA_WARN_NOOP(op, fr)                                                 \
  {                                                                            \
    Logger::ActiveLogger().log(Logger::WARN,                                   \
                               std::format("{} is a noop for {}", op, fr));    \
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
    Logger::ActiveLogger().log(
        Logger::ERROR, "Could not find the target address in the PISA program");
    return false;
  }
  // Second, find the destination port. The program may set one.
  if (!pisa_program_find_target_value(program.get(), &pgm_target_port)) {
    Logger::ActiveLogger().log(
        Logger::ERROR,
        "Could not find the target address int the PISA program");
    return false;
  }

  pisa_target_address = pgm_target.value.ipaddr;
  pisa_target_address.port = pgm_target.value.ipaddr.port;

  // Now, find out the transport type. The program must set one.
  if (!pisa_program_find_meta_value(program.get(), "TRANSPORT",
                                    &pisa_transport_value)) {
    Logger::ActiveLogger().log(
        Logger::ERROR, "Could not find the transport type in the PISA program");
    return false;
  }
  transport = Pliney::from_native_transport(pisa_transport_value.value.byte);

  return true;
}

bool PacketRunner::execute(Compilation &compilation) {

  if (!compilation) {
    return false;
  }

  auto &program = compilation.program;

  auto maybe_runner_packet{RunnerPacket::from(program)};

  if (std::holds_alternative<std::string>(maybe_runner_packet)) {
    compilation.error = std::get<std::string>(maybe_runner_packet);
    return false;
  }

  auto runner_packet = std::get<RunnerPacket>(maybe_runner_packet);

  return PacketRunner::execute(compilation, runner_packet);
}

bool PacketRunner::execute(Compilation &compilation,
                           RunnerPacket runner_packet) {

  auto &program = compilation.program;
  ip_addr_t pisa_target_address{};

  auto pisa_pgm_ip_version{runner_packet.ip_packet.version};
  auto pisa_pgm_transport_type{Pliney::from_native_transport(
      pisa_pgm_ip_version == Pliney::IpVersion::FOUR
          ? runner_packet.ip_packet.hdr.ip->protocol
          : runner_packet.ip_packet.hdr.ip6->ip6_nxt)};

  // And, now let's follow instructions.
  for (size_t insn_idx{0}; insn_idx < program->inst_count; insn_idx++) {
    switch (program->insts[insn_idx].op) {
      case EXEC_AFTER_PACKET_BUILT: {
        Logger::ActiveLogger().log(
            Logger::DEBUG,
            std::format("EXEC_PACKET_BUILDER is handled by downstream runners; "
                        "it is a no-op for Packet Runner."));
      }
      case SET_META: {
        Logger::ActiveLogger().log(
            Logger::DEBUG,
            std::format("SET_META is a no-op for Packet Runner."));
        break;
      } // SET_META
      case SET_TRANSPORT_EXTENSION: {
        // Because this replaces what was there before, release anything that
        // earlier!
        if (runner_packet.transport_packet.transportoptionhdr) {
          free(runner_packet.transport_packet.transportoptionhdr);
          runner_packet.transport_packet.transportoptionhdr_len = 0;
        }
        runner_packet.transport_packet.transportoptionhdr_len =
            program->insts[insn_idx].value.value.ptr.len;
        runner_packet.transport_packet.transportoptionhdr = (uint8_t *)calloc(
            runner_packet.transport_packet.transportoptionhdr_len,
            sizeof(uint8_t));
        memcpy(runner_packet.transport_packet.transportoptionhdr,
               program->insts[insn_idx].value.value.ptr.data,
               runner_packet.transport_packet.transportoptionhdr_len);
      } // SET_TRANSPORT_EXTENSION
      case ADD_IP_OPT_EXT: {
        if (program->insts[insn_idx].value.tpe == IP_EXT) {
          auto ip_ext{program->insts[insn_idx].value.value.ext};
          add_ip_opt_ext(&runner_packet.opts.ip_opts_exts_hdr, ip_ext);
        } else {
          Logger::ActiveLogger().log(
              Logger::ERROR, std::format("IP Options are not yet supported"));
        }
        break;
      } // ADD_IP_OPT_EXT
      case SET_FIELD: {
        switch (program->insts[insn_idx].fk.field) {
          case ICMP_CODE: {
            PISA_COWARDLY_VERSION_CHECK(
                Pliney::Transport::ICMP, pisa_pgm_transport_type,
                "Will not set an ICMP field when building/modifying a non-ICMP "
                "PISA packet");
            struct icmphdr *typed_hdr =
                (struct icmphdr *)runner_packet.transport_packet.transport;
            typed_hdr->code = program->insts[insn_idx].value.value.byte;
            break;
          }
          case ICMP_TYPE: {
            PISA_COWARDLY_VERSION_CHECK(
                Pliney::Transport::ICMP, pisa_pgm_transport_type,
                "Will not set an ICMP field when building/modifying a non-ICMP "
                "PISA packet");
            struct icmphdr *typed_hdr =
                (struct icmphdr *)runner_packet.transport_packet.transport;
            typed_hdr->type = program->insts[insn_idx].value.value.byte;
            break;
          }
          case ICMP_DEPENDS: {
            PISA_COWARDLY_VERSION_CHECK(
                Pliney::Transport::ICMP, pisa_pgm_transport_type,
                "Will not set an ICMP field when building/modifying a non-ICMP "
                "PISA packet");
            struct icmphdr *typed_hdr =
                (struct icmphdr *)runner_packet.transport_packet.transport;
            typed_hdr->un.echo.id =
                program->insts[insn_idx].value.value.four_bytes;
            typed_hdr->un.echo.sequence =
                program->insts[insn_idx].value.value.four_bytes >> 16;
            break;
          }
          case IPV6_TARGET_PORT:
          case IPV4_TARGET_PORT: {
            // We do nothing when asked to set the port to 0.
            if (!program->insts[insn_idx].value.value.ipaddr.port) {
              break;
            }

            if (!transport_has_port(pisa_pgm_transport_type)) {
              PISA_WARN_NOOP("Setting the target port",
                             to_string(pisa_pgm_transport_type));
            }
            if (pisa_pgm_transport_type == Pliney::Transport::TCP) {
              struct tcphdr *typed_hdr =
                  (struct tcphdr *)runner_packet.transport_packet.transport;
              typed_hdr->dest =
                  program->insts[insn_idx].value.value.ipaddr.port;
            } else {
              struct udphdr *typed_hdr =
                  (struct udphdr *)runner_packet.transport_packet.transport;
              typed_hdr->dest =
                  program->insts[insn_idx].value.value.ipaddr.port;
            }
            break;
          }
          case IPV4_SOURCE_PORT:
          case IPV6_SOURCE_PORT: {
            // We do nothing when asked to set the port to 0.
            if (!program->insts[insn_idx].value.value.ipaddr.port) {
              break;
            }

            if (!transport_has_port(pisa_pgm_transport_type)) {
              PISA_WARN_NOOP("Setting the target port",
                             to_string(pisa_pgm_transport_type));
            }
            if (pisa_pgm_transport_type == Pliney::Transport::TCP) {
              if (pisa_pgm_transport_type == Pliney::Transport::TCP) {
                struct tcphdr *typed_hdr =
                    (struct tcphdr *)runner_packet.transport_packet.transport;
                typed_hdr->source =
                    program->insts[insn_idx].value.value.ipaddr.port;
              } else {
                struct udphdr *typed_hdr =
                    (struct udphdr *)runner_packet.transport_packet.transport;
                typed_hdr->source =
                    program->insts[insn_idx].value.value.ipaddr.port;
              }
            }
            break;
          }
          case IPV4_TARGET: {
            PISA_COWARDLY_VERSION_CHECK(
                Pliney::IpVersion::FOUR, pisa_pgm_ip_version,
                "Will not set an IPv4 target when building/modifying a "
                "non-IPv4 PISA packet.");

            // Do not actually set the target address to 0! It's an internal
            // signal but not something that we actually obey.
            if (!program->insts[insn_idx].value.value.ipaddr.addr.ipv4.s_addr) {
              break;
            }

            struct iphdr *typed_hdr =
                (struct iphdr *)runner_packet.ip_packet.hdr.ip;
            typed_hdr->daddr =
                program->insts[insn_idx].value.value.ipaddr.addr.ipv4.s_addr;

            break;
          }
          case IPV6_TARGET: {
            PISA_COWARDLY_VERSION_CHECK(
                Pliney::IpVersion::SIX, pisa_pgm_ip_version,
                "Will not set an IPv6 target when building/modifying a "
                "non-IPv6 PISA packet.");

            // Do not actually set the target address to 0! It's an internal
            // signal but not something that we actually obey.
            if (!program->insts[insn_idx]
                     .value.value.ipaddr.addr.ipv6.s6_addr32[0] &&
                !program->insts[insn_idx]
                     .value.value.ipaddr.addr.ipv6.s6_addr32[1] &&
                !program->insts[insn_idx]
                     .value.value.ipaddr.addr.ipv6.s6_addr32[2] &&
                !program->insts[insn_idx]
                     .value.value.ipaddr.addr.ipv6.s6_addr32[3]) {
              break;
            }

            struct ip6_hdr *typed_hdr = runner_packet.ip_packet.hdr.ip6;
            typed_hdr->ip6_dst =
                program->insts[insn_idx].value.value.ipaddr.addr.ipv6;
            break;
          }
          case IPV4_SOURCE: {
            PISA_COWARDLY_VERSION_CHECK(
                Pliney::IpVersion::FOUR, pisa_pgm_ip_version,
                "Will not set an IPv4 source when building/modifying a "
                "non-IPv4 PISA packet.");

            // Do not actually set the target address to 0! It's an internal
            // signal but not something that we actually obey.
            if (!program->insts[insn_idx].value.value.ipaddr.addr.ipv4.s_addr) {
              break;
            }

            struct iphdr *typed_hdr = runner_packet.ip_packet.hdr.ip;
            typed_hdr->saddr =
                program->insts[insn_idx].value.value.ipaddr.addr.ipv4.s_addr;
            break;
          }
          case IPV6_SOURCE: {
            PISA_COWARDLY_VERSION_CHECK(
                Pliney::IpVersion::SIX, pisa_pgm_ip_version,
                "Will not set an IPv6 source when building/modifying a "
                "non-IPv6 PISA packet.");

            // Do not actually set the target address to 0! It's an internal
            // signal but not something that we actually obey.
            if (!program->insts[insn_idx]
                     .value.value.ipaddr.addr.ipv6.s6_addr32[0] &&
                !program->insts[insn_idx]
                     .value.value.ipaddr.addr.ipv6.s6_addr32[1] &&
                !program->insts[insn_idx]
                     .value.value.ipaddr.addr.ipv6.s6_addr32[2] &&
                !program->insts[insn_idx]
                     .value.value.ipaddr.addr.ipv6.s6_addr32[3]) {
              break;
            }

            struct ip6_hdr *typed_hdr = runner_packet.ip_packet.hdr.ip6;
            typed_hdr->ip6_src =
                program->insts[insn_idx].value.value.ipaddr.addr.ipv6;
            break;
          }

          case APPLICATION_BODY: {
            PISA_COWARDLY_VERSION_CHECK(
                PTR, program->insts[insn_idx].value.tpe,
                ("Will not set a body from a non-pointer value in a "
                 "PISA program."));

            // If there was a body in the packet already, release it first!
            if (runner_packet.body.body != nullptr) {
              free(runner_packet.body.body);
              runner_packet.body.len = 0;
            }

            runner_packet.body.body =
                program->insts[insn_idx].value.value.ptr.data;
            runner_packet.body.len =
                program->insts[insn_idx].value.value.ptr.len;
            break;
          }
          case IP_ECN: {
            int ecn = program->insts[insn_idx].value.value.byte;
            if (pisa_pgm_ip_version == Pliney::IpVersion::FOUR) {
              struct iphdr *typed_hdr = runner_packet.ip_packet.hdr.ip;
              typed_hdr->tos &= 0xfc;
              typed_hdr->tos |= ecn;

            } else {
              struct ip6_hdr *typed_hdr = runner_packet.ip_packet.hdr.ip6;
              typed_hdr->ip6_flow &= ~(htonl(0x3 << 20));
              typed_hdr->ip6_flow |= htonl(ecn << 20);
            }
            break;
          }
          case IP_DSCP: {
            int dscp = program->insts[insn_idx].value.value.byte;
            if (pisa_pgm_ip_version == Pliney::IpVersion::FOUR) {
              struct iphdr *typed_hdr = runner_packet.ip_packet.hdr.ip;
              typed_hdr->tos &= 0x3;
              typed_hdr->tos |= dscp;
            } else {
              struct ip6_hdr *typed_hdr = runner_packet.ip_packet.hdr.ip6;
              typed_hdr->ip6_flow &= ~(htonl(0xfc << 20));
              typed_hdr->ip6_flow |= htonl(dscp << 20);
            }

            break;
          }
          case IPV6_HL: {
            PISA_COWARDLY_VERSION_CHECK(
                Pliney::IpVersion::SIX, pisa_pgm_ip_version,
                "Will not set a hoplimit when building/modifying a non-IPv6 "
                "PISA packet.");
            int hl = program->insts[insn_idx].value.value.byte;
            struct ip6_hdr *typed_hdr = runner_packet.ip_packet.hdr.ip6;
            typed_hdr->ip6_hlim = hl;
            break;
          }
          case IPV4_TTL: {
            PISA_COWARDLY_VERSION_CHECK(
                Pliney::IpVersion::FOUR, pisa_pgm_ip_version,
                "Will not set a ttl when building/modifying a non-IPv4 PISA "
                "packet.");
            int ttl = program->insts[insn_idx].value.value.byte;
            struct iphdr *typed_hdr = runner_packet.ip_packet.hdr.ip;
            typed_hdr->ttl = ttl;
            break;
          }
          default: {
            Logger::ActiveLogger().log(
                Logger::WARN,
                std::format(
                    "Packet Runner does not yet handle fields of kind {}",
                    pisa_field_name(program->insts[insn_idx].fk.field)));
          }
        };
        break;
      } // SET_FIELD
      default: {
        Logger::ActiveLogger().log(
            Logger::WARN,
            std::format(
                "Packet Runner does not yet handle operations of kind {}",
                pisa_opcode_name(program->insts[insn_idx].op)));
      }
    }
  }

  if (runner_packet.opts.ip_opts_exts_hdr.opts_exts_count) {
    Logger::ActiveLogger().log(Logger::WARN,
                               std::format("There are extension headers."));
    if (pisa_pgm_ip_version != Pliney::IpVersion::SIX) {
      Logger::ActiveLogger().log(
          Logger::WARN, std::format("The PISA program added extension headers "
                                    "for an IPv4 packet. Skipping."));
    } else {
      // Keep a map so that setting _next extension_ field values is "easy":
      // An entry in
      // next_extension_header_offset
      // at i indicates the offset into the ip_opt_ext_hdr_raw memory
      // buffer where the ith extension header's _next extension_
      // field exists and an entry in
      // next_extension_header_value
      // at i indicates the value of the ith extension header's _next extension_
      // field.
      // TODO: Remove the assume that there are always fewer than 256 extension
      // headers.
      size_t next_extension_header_offset[256] = {};
      uint8_t next_extension_header_value[256] = {};
      uint8_t ip_packet_next_header_value{0};
      size_t total_extension_headers{0};

      // Find out how many extension headers that are supported and get an
      // array that indicates their type and an order in which to process them.
      size_t supported_ipv6_exts_count{};
      auto supported_ipv6_exts{
          supported_exts_ip_opts_exts(&supported_ipv6_exts_count)};

      // Process each supported extension header. Their value in the array
      // from supported_exts_ip_opts_exts satisfies the requirements set forth
      // in RFC8200.
      for (size_t i{0}; i < supported_ipv6_exts_count; i++) {
        auto ext_type = supported_ipv6_exts[i];
        pisa_ip_opt_ext_t coalesced_ext{coalesce_ip_opts_exts(
            runner_packet.opts.ip_opts_exts_hdr, ext_type)};

        if (!coalesced_ext.len) {
          continue;
        }

        size_t full_extension_header_len{};
        uint8_t *full_extension_header{};
        if (!to_raw_ip_opts_exts(coalesced_ext, &full_extension_header_len,
                                 &full_extension_header)) {
          // TODO
        }

        next_extension_header_offset[total_extension_headers] =
            runner_packet.opts.ip_opt_ext_hdr_raw_len;
        next_extension_header_value[total_extension_headers] =
            to_native_transport(pisa_pgm_transport_type);
        if (total_extension_headers == 0) {
          ip_packet_next_header_value =
              to_native_ext_type_ip_opts_exts(coalesced_ext.oe);
        } else {
          next_extension_header_value[total_extension_headers - 1] =
              to_native_ext_type_ip_opts_exts(coalesced_ext.oe);
        }

        runner_packet.opts.ip_opts_exts_hdr_raw =
            (uint8_t *)realloc(runner_packet.opts.ip_opts_exts_hdr_raw,
                               (runner_packet.opts.ip_opt_ext_hdr_raw_len +
                                full_extension_header_len) *
                                   sizeof(uint8_t));
        memcpy(runner_packet.opts.ip_opts_exts_hdr_raw +
                   runner_packet.opts.ip_opt_ext_hdr_raw_len,
               full_extension_header, full_extension_header_len);

        Logger::ActiveLogger().log(Logger::WARN,
                                   std::format("full_extension_header_len: {}.",
                                               full_extension_header_len));
        runner_packet.opts.ip_opt_ext_hdr_raw_len += full_extension_header_len;

        free_ip_opt_ext(coalesced_ext);
        free(full_extension_header);
        total_extension_headers++;
      }

      // Use the map to update all the extension headers' _next extension_
      // field.
      for (size_t i{0}; i < total_extension_headers; i++) {
        runner_packet.opts
            .ip_opts_exts_hdr_raw[next_extension_header_offset[i]] =
            next_extension_header_value[i];
      }

      struct ip6_hdr *typed_hdr{runner_packet.ip_packet.hdr.ip6};
      typed_hdr->ip6_nxt = ip_packet_next_header_value;
    }
  }

  // Now that we are sure what the contents of the packet hold, we _may_
  // need to update the len!
  if (pisa_pgm_ip_version == Pliney::IpVersion::SIX) {
    struct ip6_hdr *typed_hdr{runner_packet.ip_packet.hdr.ip6};
    typed_hdr->ip6_plen = htons(
        ntohs(typed_hdr->ip6_plen) + runner_packet.opts.ip_opt_ext_hdr_raw_len +
        runner_packet.transport_packet.transport_len +
        runner_packet.transport_packet.transportoptionhdr_len +
        runner_packet.body.len);
  } else {
    struct iphdr *typed_hdr{runner_packet.ip_packet.hdr.ip};
    typed_hdr->tot_len = htons(
        ntohs(typed_hdr->tot_len) + runner_packet.opts.ip_opt_ext_hdr_raw_len +
        runner_packet.transport_packet.transport_len +
        runner_packet.transport_packet.transportoptionhdr_len +
        runner_packet.body.len);
  }

  // And, if the packet is UDP transport, we should update the length in the
  // transport header!
  if (pisa_pgm_transport_type == Pliney::Transport::UDP) {
    // Update the length of the transport (if udp)!
    if (pisa_pgm_transport_type == Pliney::Transport::UDP) {
      struct udphdr *typed_hdr =
          (struct udphdr *)runner_packet.transport_packet.transport;
      typed_hdr->len =
          htons(runner_packet.body.len + Pliney::UDP_BASE_HEADER_LENGTH);
    }
  }

  // We can calculate the IP checksum now!
  if (pisa_pgm_ip_version == Pliney::IpVersion::FOUR) {
    struct iphdr *typed_hdr{runner_packet.ip_packet.hdr.ip};
    if (typed_hdr->version == Pliney::IP4_VERSION) {
      typed_hdr->check = 0;
      typed_hdr->check = compute_ip4_cksum(typed_hdr);
    }
  }

  // If we have a UDP packet (for v6), we _must_ calculate the checksum.
  if (pisa_pgm_transport_type == Pliney::Transport::UDP) {

    if (pisa_pgm_ip_version == Pliney::IpVersion::SIX) {
      struct udphdr *typed_hdr =
          (struct udphdr *)runner_packet.transport_packet.transport;

      data_p body{
          .len = runner_packet.body.len,
          .data = (uint8_t *)runner_packet.body.body,
      };
      typed_hdr->check = compute_udp_cksum(
          pisa_pgm_ip_version, (void *)runner_packet.ip_packet.hdr.ip,
          typed_hdr, body);
    }
  } else if (pisa_pgm_transport_type == Pliney::Transport::ICMP ||
             pisa_pgm_transport_type == Pliney::Transport::ICMP6) {
    if (pisa_pgm_transport_type == Pliney::Transport::ICMP) {

      struct icmphdr *typed_hdr =
          (struct icmphdr *)runner_packet.transport_packet.transport;
      data_p body{
          .len = runner_packet.body.len,
          .data = (uint8_t *)runner_packet.body.body,
      };
      // Calculate the checksum with the checksum value set to 0.
      typed_hdr->checksum = 0;
      typed_hdr->checksum = compute_icmp_cksum(typed_hdr, body);
    } else {
      Logger::ActiveLogger().log(Logger::WARN,
                                 std::format("Doing ICMPv6 checksumming."));

      struct icmp6_hdr *typed_hdr =
          (struct icmp6_hdr *)runner_packet.transport_packet.transport;
      data_p body{
          .len = runner_packet.body.len,
          .data = (uint8_t *)runner_packet.body.body,
      };
      // Calculate the checksum with the checksum value set to 0.
      typed_hdr->icmp6_cksum = 0;
      typed_hdr->icmp6_cksum =
          compute_icmp6_cksum(runner_packet.ip_packet.hdr.ip6, typed_hdr, body);
    }
  }

  // Create a buffer that holds the generated packet.
  size_t total_len{runner_packet.ip_packet.len +
                   runner_packet.opts.ip_opt_ext_hdr_raw_len +
                   runner_packet.transport_packet.transport_len +
                   runner_packet.transport_packet.transportoptionhdr_len +
                   runner_packet.body.len};
  uint8_t *packet{(uint8_t *)calloc(total_len, sizeof(uint8_t))};

  auto iphdr{static_cast<void *>(runner_packet.ip_packet.hdr.ip)};
  auto iphdr_len = runner_packet.ip_packet.len;
  // Copy the IP header into the consolidated packet.
  memcpy(packet, iphdr, iphdr_len);
  // Copy the ip options header into the consolidated header.
  memcpy(packet + iphdr_len, runner_packet.opts.ip_opts_exts_hdr_raw,
         runner_packet.opts.ip_opt_ext_hdr_raw_len);
  // Copy the transport into the consolidated header.
  memcpy(packet + iphdr_len + runner_packet.opts.ip_opt_ext_hdr_raw_len,
         runner_packet.transport_packet.transport,
         runner_packet.transport_packet.transport_len);
  // Copy the transport options into the consolidated header.
  memcpy(packet + iphdr_len + runner_packet.opts.ip_opt_ext_hdr_raw_len +
             runner_packet.transport_packet.transport_len,
         runner_packet.transport_packet.transportoptionhdr,
         runner_packet.transport_packet.transportoptionhdr_len);
  // Copy the body into the consolidated header!
  memcpy(packet + iphdr_len + runner_packet.opts.ip_opt_ext_hdr_raw_len +
             runner_packet.transport_packet.transport_len +
             runner_packet.transport_packet.transportoptionhdr_len,
         runner_packet.body.body, runner_packet.body.len);

  // The entire packet is reachable from .all, but ...
  compilation.packet.all.data = packet;
  compilation.packet.all.len = total_len;

  // ... there are views for different pieces ...
  compilation.packet.ip.data = packet;
  compilation.packet.ip.len = iphdr_len;

  // ... there are views for different pieces ...
  compilation.packet.ip_opts_exts.data = packet + iphdr_len;
  compilation.packet.ip_opts_exts.len =
      runner_packet.opts.ip_opt_ext_hdr_raw_len;

  // ... and ...
  compilation.packet.transport.data =
      packet + iphdr_len + runner_packet.opts.ip_opt_ext_hdr_raw_len;
  compilation.packet.transport.len =
      runner_packet.transport_packet.transport_len;

  compilation.packet.transport_options.data =
      packet + iphdr_len + runner_packet.opts.ip_opt_ext_hdr_raw_len +
      runner_packet.transport_packet.transport_len;
  compilation.packet.transport_options.len =
      runner_packet.transport_packet.transportoptionhdr_len;

  // ... and one more!
  compilation.packet.body.data =
      packet + iphdr_len + runner_packet.opts.ip_opt_ext_hdr_raw_len +
      runner_packet.transport_packet.transport_len +
      runner_packet.transport_packet.transportoptionhdr_len;
  compilation.packet.body.len = runner_packet.body.len;

  // Free what we allocated locally.
  free_ip_opts_exts(runner_packet.opts.ip_opts_exts_hdr);
  free(runner_packet.ip_packet.hdr.ip);
  free(runner_packet.opts.ip_opts_exts_hdr_raw);
  free(runner_packet.transport_packet.transport);
  free(runner_packet.transport_packet.transportoptionhdr);

  return true;
}

bool PacketSenderRunner::execute(Compilation &compilation) {
  if (!PacketRunner::execute(compilation)) {
    return false;
  }

  // For the packet sender, because we built a packet, it's time to let
  // the after-packet-built callbacks have their time to shine!
  for (size_t insn_idx{0}; insn_idx < compilation.program->inst_count;
       insn_idx++) {
    if (compilation.program->insts[insn_idx].op == EXEC_AFTER_PACKET_BUILT) {
      pisa_callback_t cb_info{
          compilation.program->insts[insn_idx].value.value.callback};

      exec_packet_builder_cb cb{
          reinterpret_cast<exec_packet_builder_cb>(cb_info.callback)};

      cb(compilation.packet, cb_info.cookie);
    }
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
    Logger::ActiveLogger().log(
        Logger::ERROR,
        std::format("Could not open a raw socket: {}", strerror(errno)));
    return false;
  }

  if (sendto(send_socket, compilation.packet.all.data,
             compilation.packet.all.len, 0, (struct sockaddr *)&saddrs,
             saddrs_len) < 0) {
    Logger::ActiveLogger().log(
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
      Logger::ActiveLogger().log(
          Logger::WARN,
          std::format(
              "Socket Builder Runner does not handle setting the field {}",
              pisa_field_name(instruction.fk.field)));
      break;
    }
    // The NO-OPs for the Socket Builder.
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
        Logger::ActiveLogger().log(Logger::ERROR, error);
        compilation.error = error;
        return false;
      };
      pisa_pgm_body = instruction.value;
      break;
    }
    case IP_ECN: {
      int ecn = instruction.value.value.byte;
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
        Logger::ActiveLogger().log(Logger::ERROR, error);
        compilation.error = error;
        return false;
      }
      break;
    }
    case IP_DSCP: {
      int dscp = instruction.value.value.byte;
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
        Logger::ActiveLogger().log(Logger::ERROR, error);
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
        Logger::ActiveLogger().log(Logger::ERROR, error);
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

  auto pisa_pgm_ip_version{
      Pliney::from_pisa_version(pisa_target_address.family)};

  struct sockaddr *destination = nullptr;
  int destination_len = ip_to_sockaddr(pisa_target_address, &destination);
  if (destination_len < 0) {
    std::string error{
        "Error occurred converting the target address generated by "
        "the PISA program into a system-compatible address."};
    Logger::ActiveLogger().log(Logger::ERROR, error);
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
    Logger::ActiveLogger().log(Logger::ERROR, error);
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
    Logger::ActiveLogger().log(Logger::ERROR, error);
    compilation.error = error;
    return false;
  }

  for (size_t insn_idx{0}; insn_idx < program->inst_count; insn_idx++) {
    switch (program->insts[insn_idx].op) {
      case EXEC_AFTER_SOCKET_BUILT:
      case EXEC_AFTER_PACKET_BUILT:
      case SET_META: {
        // During execution, EXEC, and SET_META operations are noops.
        break;
      } // EXEC, SET_META
      case ADD_IP_OPT_EXT: {
        if (program->insts[insn_idx].value.tpe == IP_EXT) {
          auto ip_ext{program->insts[insn_idx].value.value.ext};
          add_ip_opt_ext(&m_ip_opts_exts_hdr, ip_ext);
        } else {
          Logger::ActiveLogger().log(
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
        Logger::ActiveLogger().log(
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
      Logger::ActiveLogger().log(Logger::ERROR, error);
      compilation.error = error;
      return false;
    };
  }

  if (m_ip_opts_exts_hdr.opts_exts_count > 0) {
    if (pisa_pgm_ip_version != Pliney::IpVersion::SIX) {
      Logger::ActiveLogger().log(
          Logger::WARN, std::format("The PISA program added extension headers "
                                    "for an IPv4 connection. Skipping."));
    } else {
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
          Logger::ActiveLogger().log(Logger::ERROR, error);
          compilation.error = error;
          return false;
        }

        auto result =
            setsockopt(m_socket, IPPROTO_IPV6, ext_type, full_extension_header,
                       full_extension_header_len);
        if (result < 0) {
          Logger::ActiveLogger().log(
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
  }
  return true;
}

bool CliRunner::execute(Compilation &compilation) {
  if (!compilation) {
    return false;
  }

  if (!SocketBuilderRunner::execute(compilation)) {
    return false;
  }

  if (connect(m_socket, m_destination->get(), m_destination_len) < 0) {
    compilation.error = "Could not connect the socket.";
    Logger::ActiveLogger().log(Logger::ERROR, "Could not connect the socket.");
    return false;
  }

  int write_result = sendto(m_socket, compilation.packet.body.data,
                            compilation.packet.body.len, 0,
                            m_destination->get(), m_destination_len);

  if (write_result < 0) {
    auto error_msg = std::format("Error occurred sending data: could not "
                                 "write to the socket: {}",
                                 strerror(errno));

    Logger::ActiveLogger().log(Logger::ERROR, error_msg);
    compilation.error = error_msg;
    return false;
  }

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

  // A packet was not built so no EXEC_AFTER_PACKET_BUILT callbacks should be
  // run.

  if (connect(m_socket, m_destination->get(), m_destination_len) < 0) {
    compilation.error = "Could not connect the socket.";
    Logger::ActiveLogger().log(Logger::ERROR, "Could not connect the socket.");
    return false;
  }

  // For as many exec instructions as there are in the PISA program, do the
  // bidding!
  pisa_inst_t *pisa_exec_inst{nullptr};
  size_t last_pisa_exec_inst{0};
  while (pisa_program_find_inst(program.get(), &last_pisa_exec_inst,
                                &pisa_exec_inst, EXEC_AFTER_SOCKET_BUILT)) {
    pisa_callback_t exec_func{
        (pisa_callback_t)(pisa_exec_inst->value.value.callback.callback)};
    exec_func(m_socket, pisa_exec_inst->value.value.callback.cookie);
    last_pisa_exec_inst += 1;
  }
  return true;
}

Runner::RunnerConfigureResult
TestSenderRunner::configure(const std::vector<std::string> &args) {
  std::for_each(args.begin(), args.end(), [](std::string_view arg) {
    std::cout << std::format("runner arg: {}\n", arg);
  });

  return std::string{
      "Could not parse the runner-specific command line arguments."};
}