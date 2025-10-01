#include "packetline/executors.hpp"

#include "api/exthdrs.h"
#include "api/plugin.h"
#include "api/utils.h"
#include "packetline/logger.hpp"
#include "packetline/packetline.hpp"
#include "packetline/pipeline.hpp"
#include "packetline/utilities.hpp"

#include <cstring>
#include <iostream>
#include <memory>
#include <netinet/in.h>
#include <sys/socket.h>

maybe_packet_t SerialPipelineExecutor::execute(Pipeline &&pipeline) {

  m_pipeline = pipeline;

  auto packet = m_initial_packet;
  uint8_t connection_type{INET_STREAM};

  for (auto invocation : pipeline) {

    auto result = invocation.plugin.generate(&packet, invocation.cookie);

    if (std::holds_alternative<generate_result_t>(result)) {
      Logger::ActiveLogger()->log(Logger::DEBUG,
                                  std::format("Got a result from '{}' plugin!",
                                              invocation.plugin.name()));
      generate_result_t x = std::get<generate_result_t>(result);
      connection_type = x.connection_type;
    } else {
      std::cout << std::format("There was an error: {}\n",
                               std::get<std::string>(result));
      return std::get<std::string>(result);
    }
  }

  return packet;
}

std::optional<std::string> SerialPipelineExecutor::cleanup() {
  std::string err{};

  if (m_pipeline) {
    auto pipeline = *m_pipeline;
    for (auto plugin : pipeline) {
      auto cleanup_result = plugin.plugin.cleanup(plugin.cookie);
      if (cleanup_result) {
        auto errmsg = std::format("Error occurred cleaning up plugin {}: {}\n", plugin.plugin.name(), *cleanup_result);
        if (err.empty()) {
          err = errmsg;
        } else {
          err += "; " + errmsg;
        }
      }
    }
  }
  if (err.empty()) {
    return {};
  }
  return err;

}

bool NetworkExecutor::execute(int socket, int connection_type,
                              packet_t packet) {
  auto actual_result = packet;

  if (actual_result.header.priority != 0) {
    // Put the hoplimit into an int -- IPv6 requires it and IPv4 is okay with
    // it.
    int hoplimit = actual_result.header.priority;
    int result = 0;

    if (actual_result.target.family == INET_ADDR_V6) {
      if (connection_type == INET_DGRAM) {
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

bool InterstitialNetworkExecutor::execute(int socket, int connection_type,
                                          packet_t packet) {

  if (!NetworkExecutor::execute(socket, connection_type, packet)) {
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

  if (connection_type == INET_STREAM) {
    Logger::ActiveLogger()->log(Logger::DEBUG,
                                "Interstitial executor does nothing for "
                                "stream-oriented sockets (yet)");

  } else if (connection_type == INET_DGRAM) {
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

    if (packet.target.family == INET_ADDR_V6) {
      if (!coalesce_extensions(&packet.header_extensions, IPV6_HOPOPTS)) {
        Logger::ActiveLogger()->log(
            Logger::ERROR, "Error occurred coalescing hop-by-hop options.");
        return false;
      }

      if (packet.header_extensions.extensions_count > 0) {
        for (auto extension_i{0};
             extension_i < packet.header_extensions.extensions_count;
             extension_i++) {

          auto extension_header_len =
              ((2 /* for extension header T/L */ +
                packet.header_extensions.extensions_values[extension_i]->len +
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
              packet.header_extensions.extensions_values[extension_i]->type;
          CMSG_DATA(hdr)[0] = 0; // Next header
          CMSG_DATA(hdr)[1] = (extension_header_len / 8) - 1;

          // HbH Extension Header Data.
          memcpy(CMSG_DATA(hdr) + 2,
                 packet.header_extensions.extensions_values[extension_i]->data,
                 packet.header_extensions.extensions_values[extension_i]->len);
        }
      }
    }
  }

  return true;
}

bool CliNetworkExecutor::execute(int socket, int connection_type,
                                 packet_t packet) {

  struct sockaddr *destination = nullptr;
  int destination_len = ip_to_sockaddr(packet.target, &destination);
  if (destination_len < 0) {
    std::cerr << "Error occurred converting generated destination into "
                 "system-compatible destination.\n";
    close(socket);
    return false;
  }

  if (!NetworkExecutor::execute(socket, connection_type, packet)) {
    return false;
  }

  Logger::ActiveLogger()->log(Logger::DEBUG,
                              std::format("Trying to send a packet to {}.",
                                          stringify_ip(packet.target)));

  if (connection_type == INET_STREAM) {
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
  } else if (connection_type == INET_DGRAM) {

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

    if (packet.target.family == INET_ADDR_V6) {
      if (!coalesce_extensions(&packet.header_extensions, IPV6_HOPOPTS)) {
        Logger::ActiveLogger()->log(
            Logger::ERROR, "Error occurred coalescing hop-by-hop options.");
        return false;
      }
      if (packet.header_extensions.extensions_count > 0) {
        for (auto extension_i{0};
             extension_i < packet.header_extensions.extensions_count;
             extension_i++) {

          auto extension_header_len =
              ((2 /* for extension header T/L */ +
                packet.header_extensions.extensions_values[extension_i]->len +
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
              packet.header_extensions.extensions_values[extension_i]->type;
          CMSG_DATA(hdr)[0] = 0; // Next header
          CMSG_DATA(hdr)[1] = (extension_header_len / 8) - 1;

          // HbH Extension Header Data.
          memcpy(CMSG_DATA(hdr) + 2,
                 packet.header_extensions.extensions_values[extension_i]->data,
                 packet.header_extensions.extensions_values[extension_i]->len);
        }
      }
    }

    int write_result = sendmsg(socket, &msg, 0);

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
