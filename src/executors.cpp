#include "packetline/executors.hpp"

#include "api/exthdrs.h"
#include "api/plugin.h"
#include "api/utils.h"
#include "packetline/logger.hpp"
#include "packetline/packetline.hpp"
#include "packetline/pipeline.hpp"
#include "packetline/utilities.hpp"

#include <cstring>
#include <format>
#include <fstream>
#include <ios>
#include <iostream>
#include <memory>
#include <netinet/in.h>
#include <regex>
#include <sys/socket.h>

result_packet_tt SerialPipelineExecutor::execute(const Pipeline &pipeline) {

  auto packet = m_initial_packet;

  for (auto invocation : pipeline) {

    auto result = invocation.plugin.generate(&packet, invocation.cookie);

    if (std::holds_alternative<generate_result_t>(result)) {
      Logger::ActiveLogger()->log(Logger::DEBUG,
                                  std::format("Got a result from '{}' plugin!",
                                              invocation.plugin.name()));
      generate_result_t x = std::get<generate_result_t>(result);
    } else {
      std::cout << std::format("There was an error: {}\n",
                               std::get<std::string>(result));
      return std::get<std::string>(result);
    }
  }

  return packet;
}

bool NetworkExecutor::execute(execution_context_t execution_ctx,
                              packet_t packet) {
  int socket = std::get<int>(execution_ctx);
  auto actual_result = packet;

  if (actual_result.header.ttl != 0) {
    // Put the hoplimit into an int -- IPv6 requires it and IPv4 is okay with
    // it.
    int hoplimit = actual_result.header.ttl;
    int result = 0;

    if (actual_result.target.family == INET_ADDR_V6) {
      if (packet.transport == INET_DGRAM) {
        result = setsockopt(socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hoplimit,
                            sizeof(int));
      } else {
        Logger::ActiveLogger()->log(
            Logger::WARN, "Setting the hoplimit on a non-dgram IPv6 socket is "
                          "not supported.");
      }
    } else {
      result = setsockopt(socket, IPPROTO_IP, IP_TTL, &hoplimit, sizeof(int));
    }

    if (result < 0) {
      std::cerr << std::format(
          "There was an error setting the TTL on the socket: {}\n",
          std::strerror(errno));
      return false;
    }
  }
  return true;
}

bool InterstitialNetworkExecutor::execute(execution_context_t execution_ctx,
                                          packet_t packet) {
  int socket = std::get<int>(execution_ctx);

  if (!NetworkExecutor::execute(socket, packet)) {
    return false;
  }

  struct sockaddr *destination = nullptr;
  int destination_len = ip_to_sockaddr(packet.target, &destination);
  if (destination_len < 0) {
    std::cerr << "Error occurred converting generated destination into "
                 "system-compatible destination.\n";
    close(socket);
    return false;
  }
  m_destination = std::unique_ptr<struct sockaddr, SockaddrDeleter>(
      destination, SockaddrDeleter(destination_len));

  int tos = (packet.header.diffserv << 2) | packet.header.cong;
  if (tos != 0) {
    if (packet.target.family == INET_ADDR_V6) {
      m_toss.emplace(socket, IPPROTO_IPV6, IPV6_TCLASS, tos);
    } else {
      m_toss.emplace(socket, IPPROTO_IP, IP_TOS, tos);
    }
    if (!m_toss->ok()) {
      std::cerr << std::format(
          "There was an error setting the TOS on the socket: {}\n",
          std::strerror(errno));
      return false;
    }
  }

  if (packet.transport == INET_STREAM) {
    Logger::ActiveLogger()->log(Logger::DEBUG,
                                "Interstitial executor does nothing for "
                                "stream-oriented sockets (yet)");

  } else if (packet.transport == INET_DGRAM) {
    Logger::ActiveLogger()->log(Logger::DEBUG,
                                "Interstitial executor does nothing for "
                                "datagram-oriented sockets (yet)");
    memset(&m_msg, 0, sizeof(struct msghdr));
    m_iov.iov_base = packet.body.data;
    m_iov.iov_len = packet.body.len;

    m_msg.msg_iov = &m_iov;
    m_msg.msg_iovlen = 1;

    m_msg.msg_name = destination;
    m_msg.msg_namelen = destination_len;
    m_msg.msg_control = nullptr;
    m_msg.msg_controllen = 0;

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

          extend_cmsg(&m_msg, extension_header_len);

          struct cmsghdr *hdr = CMSG_FIRSTHDR(&m_msg);
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
    free_extensions(header_extensions);
  }
  return true;
}

InterstitialNetworkExecutor::~InterstitialNetworkExecutor() {
  if (m_msg.msg_controllen > 0) {
    free(m_msg.msg_control);
  }
}

bool CliNetworkExecutor::execute(execution_context_t execution_ctx,
                                 packet_t packet) {
  int socket = std::get<int>(execution_ctx);

  struct sockaddr *destination = nullptr;
  int destination_len = ip_to_sockaddr(packet.target, &destination);
  if (destination_len < 0) {
    std::cerr << "Error occurred converting generated destination into "
                 "system-compatible destination.\n";
    close(socket);
    return false;
  }
  auto destinations{unique_sockaddr(destination, destination_len)};

  if (!NetworkExecutor::execute(socket, packet)) {
    return false;
  }

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

    if (write_result < 0) {
      Logger::ActiveLogger()->log(
          Logger::ERROR, std::format("Error occurred sending data: could not "
                                     "write to the socket: {}",
                                     strerror(errno)));
      return false;
    }

  } else {
    Logger::ActiveLogger()->log(
        Logger::ERROR,
        std::format("Error occurred sending data: the destination address "
                    "had an invalid stream type.",
                    strerror(errno)));
  }

  return true;
}

bool XdpNetworkExecutor::execute(execution_context_t execution_ctx,
                                 packet_t packet) {
  auto xdp_path = std::filesystem::path("./skel/xdp.c");
  auto xdp_output_path = std::filesystem::path("./build/pliney_xdp.c");

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

  // Generate the xdp code.
  std::string xdp_ipv4_code{};
  std::string xdp_ipv6_code{};
  if (packet.target.family == INET_ADDR_V4) {
    if (packet.header.ttl) {
      xdp_ipv4_code += std::format("ip->ttl = {};\n", packet.header.ttl);
    }
  } else if (packet.target.family == INET_ADDR_V6) {
    xdp_ipv6_code += std::format("ipv6->ip6_hlim = {};\n", packet.header.ttl);
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
