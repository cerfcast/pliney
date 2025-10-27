#include "packetline/executors/result.hpp"
#include "packetline/executors/pipeline.hpp"

#include "api/exthdrs.h"
#include "api/plugin.h"
#include "api/utils.h"
#include "packetline/logger.hpp"
#include "packetline/utilities.hpp"

#include <cstring>
#include <format>
#include <iostream>
#include <memory>
#include <netinet/in.h>
#include <sys/socket.h>
#include <variant>

bool ResultExecutor::execute(PipelineResult execution_ctx) {

  if (!execution_ctx.success) {
    return false;
  }

  auto socket = execution_ctx.socket;
  auto packet = *execution_ctx.packet;

  if (packet.header.ttl != 0) {
    // Put the hoplimit into an int -- IPv6 requires it and IPv4 is okay with
    // it.
    int hoplimit = packet.header.ttl;
    int result = 0;

    if (packet.target.family == INET_ADDR_V6) {
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

bool InterstitialResultExecutor::execute(PipelineResult execution_ctx) {

  if (!execution_ctx.success || !execution_ctx.packet) {
    return false;
  }

  int socket = execution_ctx.socket;
  auto packet = *execution_ctx.packet;

  if (!ResultExecutor::execute(execution_ctx)) {
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

InterstitialResultExecutor::~InterstitialResultExecutor() {
  if (m_msg.msg_controllen > 0) {
    free(m_msg.msg_control);
  }
}

bool CliResultExecutor::execute(PipelineResult execution_ctx) {

  if (!execution_ctx.success || !execution_ctx.packet) {
    return false;
  }

  int socket = execution_ctx.socket;
  auto packet = *execution_ctx.packet;

  struct sockaddr *destination = nullptr;
  int destination_len = ip_to_sockaddr(packet.target, &destination);
  if (destination_len < 0) {
    std::cerr << "Error occurred converting generated destination into "
                 "system-compatible destination.\n";
    close(socket);
    return false;
  }
  auto destinations{unique_sockaddr(destination, destination_len)};

  if (!ResultExecutor::execute(execution_ctx)) {
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

void PipelineExecutorBuilder::with_name(const std::string &name,
                                        pipeline_executor_builder_t builder) {
  builders[name] = builder;
}

std::variant<std::string, std::unique_ptr<PipelineExecutor>>
PipelineExecutorBuilder::by_name(const std::string &name) {

  if (builders.contains(name)) {
    return std::variant<std::string, std::unique_ptr<PipelineExecutor>>{
        std::move(builders[name]())};
  }

  return std::format("No builder named {} is registered.", name);
}
