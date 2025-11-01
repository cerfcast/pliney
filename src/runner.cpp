#include "packetline/runner.hpp"
#include "pisa/compiler.hpp"
#include "pisa/pipeline.hpp"

#include "packetline/logger.hpp"
#include "packetline/utilities.hpp"
#include "pisa/pisa.h"
#include "pisa/plugin.h"
#include "pisa/types.h"

#include <cstdint>
#include <cstring>
#include <format>
#include <iostream>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/socket.h>

bool PacketRunner::execute(CompilationResult &execution_ctx) {

  if (!execution_ctx.success || !execution_ctx.program) {
    return false;
  }

  auto program = execution_ctx.program;

  pisa_value_t pgm_body{};
  pisa_value_t pgm_dest{};
  pisa_value_t pisa_transport_value = {.tpe = BYTE};

  // First, find the destination. The program must set one.
  if (!pisa_program_find_target_value(program, &pgm_dest)) {
    Logger::ActiveLogger()->log(Logger::ERROR,
                                "Could not find the target value!");
    return false;
  }

  // Now, find out the transport type. The program must set one.
  if (!pisa_program_find_meta_value(program, "TRANSPORT",
                                    &pisa_transport_value)) {
    Logger::ActiveLogger()->log(Logger::ERROR,
                                "Could not find the transport value!");
    return false;
  }
  auto transport_value = pisa_transport_value.value.byte;
  auto target_family{pgm_dest.value.ipaddr.family};

  // Let's say that there is an IP header
  size_t iphdr_len{target_family == INET_ADDR_V4 ? size_t{20} : size_t{40}};
  void *iphdr{(void *)calloc(iphdr_len, sizeof(uint8_t))};

  // Put some initial values into the packet.
  if (target_family == INET_ADDR_V4) {
    struct iphdr *typed_hdr = (struct iphdr *)iphdr;
    typed_hdr->version = 0x4;
    typed_hdr->ihl = 0x5;
    if (transport_value == INET_STREAM) {
      typed_hdr->protocol = IPPROTO_TCP;
    } else if (transport_value == INET_DGRAM) {
      typed_hdr->protocol = IPPROTO_UDP;
    }
  } else {
    struct ip6_hdr *typed_hdr = (struct ip6_hdr *)iphdr;
    typed_hdr->ip6_vfc |= 0x6 << 4;
    if (transport_value == INET_STREAM) {
      typed_hdr->ip6_nxt = IPPROTO_TCP;
    } else if (transport_value == INET_DGRAM) {
      typed_hdr->ip6_nxt = IPPROTO_UDP;
    }
  }

  // Let's say that there is a transport header;
  size_t transport_len{transport_value == INET_DGRAM ? size_t{8} : size_t{20}};
  void *transport{(void *)calloc(transport_len, sizeof(uint8_t))};

  for (size_t insn_idx{0}; insn_idx < program->inst_count; insn_idx++) {
    switch (program->insts[insn_idx].op) {
    case SET_META: {
      Logger::ActiveLogger()->log(
          Logger::DEBUG, std::format("SET_META is a no-op for Packet Runner."));
      break;
    } // SET_META
    case SET_FIELD: {
      switch (program->insts[insn_idx].fk.field) {
      case IPV4_TARGET: {
        if (target_family != INET_ADDR_V4) {
          Logger::ActiveLogger()->log(
              Logger::WARN,
              std::format(
                  "Will not set an IPv4 target on a non-IPv4 PISA program."));
        }
        struct iphdr *typed_hdr = (struct iphdr *)iphdr;
        typed_hdr->daddr =
            program->insts[insn_idx].value.value.ipaddr.addr.ipv4.s_addr;
        break;
      }
      case IPV6_TARGET: {
        if (target_family != INET_ADDR_V6) {
          Logger::ActiveLogger()->log(
              Logger::WARN,
              std::format(
                  "Will not set an IPv6 target on a non-IPv6 PISA program."));
        }
        struct ip6_hdr *typed_hdr = (struct ip6_hdr *)iphdr;
        typed_hdr->ip6_dst =
            program->insts[insn_idx].value.value.ipaddr.addr.ipv6;
        break;
      }
      case BODY: {
        if (program->insts[insn_idx].value.tpe != PTR) {
          Logger::ActiveLogger()->log(
              Logger::WARN,
              std::format("Will not set a body from a non-pointer value."));
          return false;
        };
        pgm_body = program->insts[insn_idx].value;
        if (target_family == INET_ADDR_V4) {
          struct iphdr *typed_hdr = (struct iphdr *)iphdr;
          typed_hdr->tot_len = htons((typed_hdr->ihl * 4) + transport_len +
                                     pgm_body.value.ptr.len);
        } else {
          struct ip6_hdr *typed_hdr = (struct ip6_hdr *)iphdr;
          typed_hdr->ip6_plen = htons(transport_len + pgm_body.value.ptr.len);
        }
        break;
      }
      case IPV6_ECN: {
        int ecn = program->insts[insn_idx].value.value.byte;
        if (target_family != INET_ADDR_V6) {
          Logger::ActiveLogger()->log(
              Logger::WARN, std::format("Will not set an IPv6 ECN value on a "
                                        "non-IPv6 PISA program."));
        }
        struct ip6_hdr *typed_hdr = (struct ip6_hdr *)iphdr;
        typed_hdr->ip6_flow &= ~(htonl(0x3 << 20));
        typed_hdr->ip6_flow |= htonl(ecn << 20);

        break;
      }
      case IPV4_ECN: {
        int ecn = program->insts[insn_idx].value.value.byte;
        if (target_family != INET_ADDR_V4) {
          Logger::ActiveLogger()->log(
              Logger::WARN, std::format("Will not set an IPv4 ECN value on a "
                                        "non-IPv4 PISA program."));
        }
        struct iphdr *typed_hdr = (struct iphdr *)iphdr;
        // First, remove the previous ECN value.
        typed_hdr->tos &= 0xfc;
        // Now, set the ECN.
        typed_hdr->tos |= ecn;
        break;
      }
      case IPV6_DSCP: {
        int dscp = program->insts[insn_idx].value.value.byte;
        if (target_family != INET_ADDR_V6) {
          Logger::ActiveLogger()->log(
              Logger::WARN, std::format("Will not set an IPv6 DSCP value on a "
                                        "non-IPv6 PISA program."));
        }
        struct ip6_hdr *typed_hdr = (struct ip6_hdr *)iphdr;
        typed_hdr->ip6_flow &= ~(htonl(0xfc << 20));
        typed_hdr->ip6_flow |= htonl(dscp << 20);

        break;
      }
      case IPV4_DSCP: {
        int dscp = program->insts[insn_idx].value.value.byte;
        if (target_family != INET_ADDR_V4) {
          Logger::ActiveLogger()->log(
              Logger::WARN, std::format("Will not set an IPv4 DSCP value on a "
                                        "non-IPv4 PISA program."));
        }
        struct iphdr *typed_hdr = (struct iphdr *)iphdr;
        typed_hdr->tos &= 0x3;
        typed_hdr->tos |= dscp;
        break;
      }
      case IPV6_HL: {
        int hl = program->insts[insn_idx].value.value.byte;
        if (target_family != INET_ADDR_V6) {
          Logger::ActiveLogger()->log(
              Logger::WARN,
              std::format(
                  "Will not set a hoplimit on a non-IPv6 PISA program."));
        }
        struct ip6_hdr *typed_hdr = (struct ip6_hdr *)iphdr;
        typed_hdr->ip6_hlim = hl;
        break;
      }
      case IPV4_TTL: {
        int ttl = program->insts[insn_idx].value.value.byte;
        if (target_family != INET_ADDR_V4) {
          Logger::ActiveLogger()->log(
              Logger::WARN,
              std::format("Will not set a TTL on a non-IPv4 PISA program."));
        }
        struct iphdr *typed_hdr = (struct iphdr *)iphdr;
        typed_hdr->ttl = ttl;
        break;
      }
      default: {
        Logger::ActiveLogger()->log(
            Logger::WARN,
            std::format("Packet Runner does not yet handle fields of kind {}",
                        pisa_field_name(program->insts[insn_idx].fk.field)));
      }
      };
      break;
    } // SET_FIELD
    default: {
      Logger::ActiveLogger()->log(
          Logger::WARN,
          std::format("Packet Runner does not yet handle operations of kind {}",
                      pisa_opcode_name(program->insts[insn_idx].op)));
    }
    }
  }

  size_t total_len{iphdr_len + transport_len + pgm_body.value.ptr.len};

  uint8_t *packet{(uint8_t *)calloc(total_len, sizeof(uint8_t))};

  memcpy(packet, iphdr, iphdr_len);
  memcpy(packet + iphdr_len, transport, transport_len);
  memcpy(packet + iphdr_len + transport_len, pgm_body.value.ptr.data,
         pgm_body.value.ptr.len);

  free(iphdr);
  free(transport);

  execution_ctx.packet.ip.data = packet;
  execution_ctx.packet.ip.len = iphdr_len;
  execution_ctx.packet.transport.data = packet + iphdr_len;
  execution_ctx.packet.transport.len = transport_len;
  execution_ctx.packet.body.data = packet + iphdr_len + transport_len;
  execution_ctx.packet.body.len = pgm_body.value.ptr.len;

  for (auto invocation : m_pipeline) {
    invocation.plugin.observe(program, &execution_ctx.packet,
                              invocation.cookie);
  }

  return true;
}

bool CliRunner::execute(CompilationResult &execution_ctx) {

  if (!execution_ctx.success || !execution_ctx.program) {
    return false;
  }

  auto program = execution_ctx.program;

  pisa_value_t pgm_body{};
  pisa_value_t pgm_dest;
  pisa_value_t pisa_transport_value = {.tpe = BYTE};

  // First, find the destination. The program must set one.
  if (!pisa_program_find_target_value(program, &pgm_dest)) {
    Logger::ActiveLogger()->log(Logger::ERROR,
                                "Could not find the target value!");
    return false;
  }
  auto pliney_destination = pgm_dest.value.ipaddr;
  struct sockaddr *destination = nullptr;
  int destination_len = ip_to_sockaddr(pgm_dest.value.ipaddr, &destination);
  if (destination_len < 0) {
    std::cerr << "Error occurred converting generated destination into "
                 "system-compatible destination.\n";
    return false;
  }
  auto destination_d{
      unique_sockaddr((struct sockaddr *)destination, destination_len)};

  // Now, find out the transport type. The program must set one.
  if (!pisa_program_find_meta_value(program, "TRANSPORT",
                                    &pisa_transport_value)) {
    Logger::ActiveLogger()->log(Logger::ERROR,
                                "Could not find the transport value!");
    return false;
  }
  auto transport_value = pisa_transport_value.value.byte;

  // Now, open a socket!
  int socket{0};
  auto socket_success =
      ip_to_socket(pliney_destination, transport_value, &socket);
  if (!socket_success || socket < 0) {
    std::string reason{"Ill-formatted target"};
    if (socket_success) {
      reason = strerror(errno);
    }
    Logger::ActiveLogger()->log(
        Logger::ERROR,
        std::format("Could not open a {} socket to the target address ({}): "
                    "{}.",
                    transport_value == INET_STREAM ? "TCP" : "UDP",
                    stringify_ip(pgm_dest.value.ipaddr), reason));
    return false;
  }

  std::optional<Swapsockopt<int>> ttlhl{};
  std::optional<Swapsockopt<int>> toss{};

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
      case BODY: {
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
                               ? INET_ADDR_V6
                               : INET_ADDR_V4;
        if (pliney_destination.family != set_type) {
          // Better error message.
          Logger::ActiveLogger()->log(
              Logger::WARN,
              std::format("Will not set the IPV4 ECN on an non-IPv4 packet"));
          break;
        }
        if (toss) {
          (*toss).again(ecn, 0x3);
        } else {
          if (pliney_destination.family == INET_ADDR_V6) {
            toss.emplace(socket, IPPROTO_IPV6, IPV6_TCLASS, ecn, 0x3);
          } else {
            toss.emplace(socket, IPPROTO_IP, IP_TOS, ecn, 0x3);
          }
        }
        if (!toss->ok()) {
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
                               ? INET_ADDR_V6
                               : INET_ADDR_V4;
        if (pliney_destination.family != set_type) {
          // Better error message.
          Logger::ActiveLogger()->log(
              Logger::WARN,
              std::format("Will not set the DSCP on an non-IPv4 packet"));
          break;
        }
        if (toss) {
          (*toss).again(dscp, 0xfc);
        } else {
          if (pliney_destination.family == INET_ADDR_V6) {
            toss.emplace(socket, IPPROTO_IPV6, IPV6_TCLASS, dscp, 0xfc);
          } else {
            toss.emplace(socket, IPPROTO_IP, IP_TOS, dscp, 0xfc);
          }
        }
        if (!toss->ok()) {
          std::cerr << std::format(
              "There was an error setting the DSCP on the socket: {}\n",
              std::strerror(errno));
          return false;
        }
        break;
      }

      case IPV6_HL: {
        int hoplimit = program->insts[insn_idx].value.value.byte;
        if (pliney_destination.family != INET_ADDR_V6) {
          Logger::ActiveLogger()->log(
              Logger::WARN,
              std::format("Will not set the IPV6 TTL on an non-IPv6 packet"));
          break;
        }

        ttlhl.emplace(socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, hoplimit);
        if (!ttlhl->ok()) {
          std::cerr << std::format(
              "There was an error setting the hoplimit on the socket: {}\n",
              std::strerror(errno));
          return false;
        }
        break;
      }
      case IPV4_TTL: {
        int hoplimit = program->insts[insn_idx].value.value.byte;
        if (pliney_destination.family != INET_ADDR_V4) {
          Logger::ActiveLogger()->log(
              Logger::WARN,
              std::format("Will not set the IPV4 TTL on an non-IPv4 packet"));
          break;
        }
        ttlhl.emplace(socket, IPPROTO_IP, IP_TTL, hoplimit);
        if (!ttlhl->ok()) {
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

  // Now, do I have to connect?
  if (transport_value == INET_STREAM) {
    auto connect_result = connect(socket, destination, destination_len);
    Logger::ActiveLogger()->log(
        Logger::ERROR,
        std::format("Could not connect to the target address: {}",
                    strerror(errno)));
  }

#if 0
  std::optional<Swapsockopt<int>> toss{};
  int tos = (packet.header.diffserv << 2) | packet.header.cong;

  if (tos != 0) {
    if (packet.target.family == INET_ADDR_V6) {
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
    if (packet.target.family == INET_ADDR_V6) {
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

  struct msghdr msg {};
  struct iovec iov {};

  memset(&msg, 0, sizeof(struct msghdr));
  iov.iov_base = nullptr;
  iov.iov_len = 0;

  if (pgm_body.value.ptr.len) {
    iov.iov_base = pgm_body.value.ptr.data;
    iov.iov_len = pgm_body.value.ptr.len;
  }

  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  msg.msg_name = destination;
  msg.msg_namelen = destination_len;

  msg.msg_control = nullptr;
  msg.msg_controllen = 0;

  int write_result = sendmsg(socket, &msg, 0);

  if (write_result < 0) {
    Logger::ActiveLogger()->log(
        Logger::ERROR, std::format("Error occurred sending data: could not "
                                   "write to the socket: {}",
                                   strerror(errno)));
    return false;
  }

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
