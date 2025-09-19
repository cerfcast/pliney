#ifndef _EXECUTORS_HPP
#define _EXECUTORS_HPP

#include "api/exthdrs.h"
#include "api/utils.h"
#include "packetline/logger.hpp"
#include "packetline/packetline.hpp"
#include "packetline/pipeline.hpp"

#include <cstring>
#include <iostream>
#include <sys/socket.h>

class PipelineExecutor {
public:
  virtual maybe_packet_t execute(Pipeline &&plugins) = 0;
};

class SerialPipelineExecutor : public PipelineExecutor {
public:
  explicit SerialPipelineExecutor(packet_t packet = {}) {
    m_initial_packet = packet;
    packet.header_extensions = {.extensions_count = 0,
                                .extensions_values = NULL};
  }

  maybe_packet_t execute(Pipeline &&pipeline) override {
    auto packet = m_initial_packet;
    uint8_t connection_type{INET_STREAM};

    for (auto invocation : pipeline) {

      auto result = invocation.plugin.generate(&packet, invocation.cookie);

      if (std::holds_alternative<generate_result_t>(result)) {
        Logger::ActiveLogger()->log(
            Logger::DEBUG, std::format("Got a result from '{}' plugin!",
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

private:
  packet_t m_initial_packet{};
};

class NetworkExecutor {
public:
  virtual bool execute(int socket, int connection_type, packet_t packet) = 0;
};

class InterstitialNetworkExecutor : public NetworkExecutor {
public:
  bool execute(int socket, int connection_type, packet_t packet) {
    auto actual_result = packet;

    struct sockaddr *destination = nullptr;
    int destination_len = ip_to_sockaddr(actual_result.target, &destination);
    if (destination_len < 0) {
      std::cerr << "Error occurred converting generated destination into "
                   "system-compatible destination.\n";
      return false;
    }

    if (actual_result.header.priority != 0) {
      // Put the hoplimit into an int -- IPv6 requires it and IPv4 is okay with
      // it.
      int hoplimit = actual_result.header.priority;
      int result = 0;

      if (actual_result.target.family == INET_ADDR_V6) {
        if (connection_type == INET_DGRAM) {
          result = setsockopt(socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                              &hoplimit, sizeof(int));
        } else {
          Logger::ActiveLogger()->log(
              Logger::WARN,
              "Setting the hoplimit on a non-dgram IPv6 socket is "
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

    if (connection_type == INET_STREAM) {
      Logger::ActiveLogger()->log(Logger::DEBUG,
                                  "Interstitial executor does nothing for "
                                  "stream-oriented sockets (yet)\n");

    } else if (connection_type == INET_DGRAM) {
      Logger::ActiveLogger()->log(Logger::DEBUG,
                                  "Interstitial executor does nothing for "
                                  "datagram-oriented sockets (yet)\n");

      if (!coalesce_extensions(&actual_result.header_extensions,
                               IPV6_HOPOPTS)) {
        Logger::ActiveLogger()->log(
            Logger::ERROR, "Error occurred coalescing hop-by-hop options.");
        return false;
      }

      memset(&m_msg, 0, sizeof(struct msghdr));
      m_iov.iov_base = actual_result.body.data;
      m_iov.iov_len = actual_result.body.len;

      m_msg.msg_iov = &m_iov;
      m_msg.msg_iovlen = 1;

      m_msg.msg_name = destination;
      m_msg.msg_namelen = destination_len;

      if (actual_result.header_extensions.extensions_count > 0) {

        // First, calculate _all_ the sizes for the extension headers.
        size_t cmsg_space_len_needed = 0;
        for (auto extension_i{0};
             extension_i < actual_result.header_extensions.extensions_count;
             extension_i++) {

          auto extension_header_len =
              ((2 /* for extension header T/L */ +
                actual_result.header_extensions.extensions_values[extension_i]
                    ->len +
                (8 - 1)) /
               8) *
              8;
          Logger::ActiveLogger()->log(
              Logger::DEBUG,
              std::format("extension_header_len: {}", extension_header_len));

          cmsg_space_len_needed += CMSG_LEN(extension_header_len);
        }
        auto cmsg_space_len = CMSG_ALIGN(cmsg_space_len_needed);
        uint8_t *cmsg_buf = (uint8_t *)calloc(cmsg_space_len, sizeof(uint8_t));

        m_msg.msg_control = cmsg_buf;
        m_msg.msg_controllen = cmsg_space_len;

        struct cmsghdr *hdr = CMSG_FIRSTHDR(&m_msg);
        for (auto extension_i{0};
             extension_i < actual_result.header_extensions.extensions_count;
             extension_i++, hdr = CMSG_NXTHDR(&m_msg, hdr)) {

          auto extension_header_len =
              ((2 /* for extension header T/L */ +
                actual_result.header_extensions.extensions_values[extension_i]
                    ->len +
                (8 - 1)) /
               8) *
              8;
          hdr->cmsg_type =
              actual_result.header_extensions.extensions_values[extension_i]
                  ->type;
          hdr->cmsg_level = SOL_IPV6;
          hdr->cmsg_len = CMSG_LEN(extension_header_len);

          CMSG_DATA(hdr)[0] = 0; // Next header
          CMSG_DATA(hdr)[1] = (extension_header_len / 8) - 1;

          // HbH Extension Header Data.
          memcpy(CMSG_DATA(hdr) + 2,
                 actual_result.header_extensions.extensions_values[extension_i]
                     ->data,
                 actual_result.header_extensions.extensions_values[extension_i]
                     ->len);
        }
      }
    }

    return true;
  }

  struct msghdr get_msg() const { return m_msg; }

private:
  struct msghdr m_msg{};
  struct iovec m_iov{};
};

class CliNetworkExecutor : public NetworkExecutor {
public:
  bool execute(int socket, int connection_type, packet_t packet) {
    auto actual_result = packet;

    struct sockaddr *destination = nullptr;
    int destination_len = ip_to_sockaddr(actual_result.target, &destination);
    if (destination_len < 0) {
      std::cerr << "Error occurred converting generated destination into "
                   "system-compatible destination.\n";
      close(socket);
      return false;
    }

    if (ip_set(actual_result.source)) {
      sockaddr_storage saddr{};
      size_t saddr_len{0};

      if (actual_result.source.family == INET_ADDR_V4) {
        sockaddr_in *source{reinterpret_cast<sockaddr_in *>(&saddr)};
        saddr_len = sizeof(sockaddr_in);

        source->sin_addr = actual_result.source.addr.ipv4;
        source->sin_family = AF_INET;
        source->sin_port = actual_result.source.port;

      } else {
        sockaddr_in6 *source{reinterpret_cast<sockaddr_in6 *>(&saddr)};
        saddr_len = sizeof(sockaddr_in6);

        source->sin6_addr = actual_result.source.addr.ipv6;
        source->sin6_family = AF_INET6;
        source->sin6_port = actual_result.source.port;
        source->sin6_flowinfo = 0;
        source->sin6_scope_id = 0;
      }

      if (bind(socket, (struct sockaddr *)&saddr, saddr_len) < 0) {
        Logger::ActiveLogger()->log(
            Logger::ERROR,
            std::format("Could not bind to a source address: {}!",
                        std::strerror(errno)));
        close(socket);
        return false;
      }
    }

    if (actual_result.header.priority != 0) {
      // Put the hoplimit into an int -- IPv6 requires it and IPv4 is okay with
      // it.
      int hoplimit = actual_result.header.priority;
      int result = 0;

      if (actual_result.target.family == INET_ADDR_V6) {
        if (connection_type == INET_DGRAM) {
          result = setsockopt(socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                              &hoplimit, sizeof(int));
        } else {
          Logger::ActiveLogger()->log(
              Logger::WARN,
              "Setting the hoplimit on a non-dgram IPv6 socket is "
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

    Logger::ActiveLogger()->log(
        Logger::DEBUG, std::format("Trying to send a packet to {}.",
                                   stringify_ip(actual_result.target)));

    if (connection_type == INET_STREAM) {
      auto connect_result = connect(socket, destination, destination_len);
      if (connect_result < 0) {
        Logger::ActiveLogger()->log(
            Logger::ERROR, std::format("Error occurred sending data: could not "
                                       "connect the socket: {}",
                                       strerror(errno)));
        return false;
      }
      if (write(socket, actual_result.body.data, actual_result.body.len) < 0) {
        Logger::ActiveLogger()->log(
            Logger::ERROR, std::format("Error occurred sending data: could not "
                                       "write the body of the packet: {}",
                                       strerror(errno)));
      };
    } else if (connection_type == INET_DGRAM) {
      if (!coalesce_extensions(&actual_result.header_extensions,
                               IPV6_HOPOPTS)) {
        Logger::ActiveLogger()->log(
            Logger::ERROR, "Error occurred coalescing hop-by-hop options.");
        return false;
      }

      struct msghdr msg{};
      struct iovec iov{};

      memset(&msg, 0, sizeof(struct msghdr));
      iov.iov_base = actual_result.body.data;
      iov.iov_len = actual_result.body.len;

      msg.msg_iov = &iov;
      msg.msg_iovlen = 1;

      msg.msg_name = destination;
      msg.msg_namelen = destination_len;

      if (actual_result.header_extensions.extensions_count > 0) {

        // First, calculate _all_ the sizes for the extension headers.
        size_t cmsg_space_len_needed = 0;
        for (auto extension_i{0};
             extension_i < actual_result.header_extensions.extensions_count;
             extension_i++) {

          auto extension_header_len =
              ((2 /* for extension header T/L */ +
                actual_result.header_extensions.extensions_values[extension_i]
                    ->len +
                (8 - 1)) /
               8) *
              8;
          Logger::ActiveLogger()->log(
              Logger::DEBUG,
              std::format("extension_header_len: {}", extension_header_len));

          cmsg_space_len_needed += CMSG_LEN(extension_header_len);
        }
        auto cmsg_space_len = CMSG_ALIGN(cmsg_space_len_needed);
        uint8_t *cmsg_buf = (uint8_t *)calloc(cmsg_space_len, sizeof(uint8_t));

        msg.msg_control = cmsg_buf;
        msg.msg_controllen = cmsg_space_len;

        struct cmsghdr *hdr = CMSG_FIRSTHDR(&msg);
        for (auto extension_i{0};
             extension_i < actual_result.header_extensions.extensions_count;
             extension_i++, hdr = CMSG_NXTHDR(&msg, hdr)) {

          auto extension_header_len =
              ((2 /* for extension header T/L */ +
                actual_result.header_extensions.extensions_values[extension_i]
                    ->len +
                (8 - 1)) /
               8) *
              8;
          hdr->cmsg_type =
              actual_result.header_extensions.extensions_values[extension_i]
                  ->type;
          hdr->cmsg_level = SOL_IPV6;
          hdr->cmsg_len = CMSG_LEN(extension_header_len);

          CMSG_DATA(hdr)[0] = 0; // Next header
          CMSG_DATA(hdr)[1] = (extension_header_len / 8) - 1;

          // HbH Extension Header Data.
          memcpy(CMSG_DATA(hdr) + 2,
                 actual_result.header_extensions.extensions_values[extension_i]
                     ->data,
                 actual_result.header_extensions.extensions_values[extension_i]
                     ->len);
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
};

#endif
