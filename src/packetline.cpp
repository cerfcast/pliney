#include <arpa/inet.h>
#include <bits/types/struct_iovec.h>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <endian.h>
#include <filesystem>
#include <format>
#include <iostream>
#include <netinet/in.h>
#include <numeric>
#include <sys/socket.h>
#include <unistd.h>
#include <variant>
#include <vector>

#include "api/exthdrs.h"
#include "api/plugin.h"
#include "api/utils.h"
#include "packetline/cli.hpp"
#include "packetline/logger.hpp"
#include "packetline/packetline.hpp"
#include "packetline/pipeline.hpp"

#include <unistd.h>

#include <errno.h>

extern int errno;

#if 0
template <typename W>
class Trimit : public std::ranges::range_adaptor_closure<Trimit<W>> {
  const W m_of_what;

  template <typename T>
  static std::string trim(T &&to_trim, W of_what) {
    const auto not_space = [of_what](const char c) { return c != of_what; };
    const auto first_non_space =
        std::find_if(to_trim.begin(), to_trim.end(), not_space);
    const auto last_non_space =
        std::find_if(to_trim.rbegin(), to_trim.rend(), not_space);
    return std::string(first_non_space, last_non_space.base());
  }

public:
  Trimit(W of_what) : m_of_what(of_what) {}

  template <std::ranges::range T> constexpr auto operator()(const T &&x) {
    return std::ranges::transform_view(
        x, [this](auto x) { return trim(x, m_of_what); });
  }
};
#endif
;

class PipelineExecutor {
public:
  virtual maybe_packet_t execute(Pipeline &&plugins) = 0;
};

class SerialPipelineExecutor : public PipelineExecutor {
public:
  maybe_packet_t execute(Pipeline &&pipeline) override {

    packet_t packet{};
    packet.header_extensions = {.extensions_count = 0,
                                .extensions_values = NULL};
    uint8_t connection_type{INET_STREAM};

    auto debug_logger = Logger::active_logger(Logger::DEBUG);

    for (auto invocation : pipeline) {

      auto result = invocation.plugin.generate(&packet, invocation.cookie);

      if (std::holds_alternative<generate_result_t>(result)) {
        debug_logger.log(std::format("Got a result from '{}' plugin!\n",
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
};

int main(int argc, const char **argv) {
  auto plugin_path = std::filesystem::path("./build");
  auto plugins = PluginDir{plugin_path};
  auto loaded_plugins = plugins.plugins();

  uint8_t connection_type = INET_STREAM;

  if (loaded_plugins.empty()) {
    std::cerr << "No plugins loaded.\n";
    return 1;
  }

  // Determine where the pipeline starts ...
  size_t pipeline_start{0};
  auto pipeline_start_found =
      Cli::find_pipeline_start(argc, argv, &pipeline_start);

  if (!pipeline_start_found) {
    std::cerr << "No pipeline found.\n";
    return 1;
  }

  // Determine whether there are arguments for pliney, before the pipeline
  // starts.
  for (size_t pliney_arg_idx{1}; pliney_arg_idx < pipeline_start;
       pliney_arg_idx++) {

#define HAS_ANOTHER_ARG                                                        \
  if (pliney_arg_idx + 1 >= pipeline_start) {                                  \
    std::cerr << std::format("Missing value for parameter {}\n", maybe_arg);   \
    return 1;                                                                  \
  } else {                                                                     \
    pliney_arg_idx++;                                                          \
  }

    std::string maybe_arg{argv[pliney_arg_idx]};

    if (maybe_arg.starts_with('-')) {
      std::string arg{maybe_arg.substr(1)};
      if (arg == "type") {
        HAS_ANOTHER_ARG;
        if (!Cli::parse_connection_type(argv[pliney_arg_idx],
                                        connection_type)) {
          std::cerr << std::format("Invalid connection type given: {}",
                                   argv[pliney_arg_idx]);
          return 1;
        }
        continue;
      }
    }
    std::cerr << std::format("Unrecognized argument: {}\n",
                             argv[pliney_arg_idx]);
    return 1;
  }

  auto pipeline =
      Pipeline{argv + pipeline_start + 1, std::move(loaded_plugins)};

  if (!pipeline.ok()) {
    auto pipeline_errs = std::accumulate(
        pipeline.error_begin(), pipeline.error_end(), std::string{},
        [](const std::string existing, const std::string next) {
          if (existing.length()) {
            return existing + "; " + next;
          }
          return next;
        });
    std::cerr << std::format("Error occurred configuring pipeline: {}\n",
                             pipeline_errs);
    return 1;
  }

  auto executor = SerialPipelineExecutor{};
  auto maybe_result = executor.execute(std::move(pipeline));

  auto debug_logger = Logger::active_logger(Logger::DEBUG);
  auto error_logger = Logger::active_logger(Logger::ERROR);

  if (std::holds_alternative<packet_t>(maybe_result)) {

    auto actual_result = std::get<packet_t>(maybe_result);
    auto skt = ip_to_socket(actual_result.target, connection_type);

    if (skt < 0) {
      std::cerr << std::format(
          "Error occurred sending data: could not open the socket: \n",
          strerror(errno));
      return -1;
    }

    struct sockaddr *destination = nullptr;
    int destination_len = ip_to_sockaddr(actual_result.target, &destination);
    if (destination_len < 0) {
      std::cerr << "Error occurred converting generated destination into "
                   "system-compatible destination.\n";
      close(skt);
      return -1;
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

      if (bind(skt, (struct sockaddr *)&saddr, saddr_len) < 0) {
        error_logger.log(std::format(
            "Could not bind to a source address: {}!\n", std::strerror(errno)));
        close(skt);
        return -1;
      }
    }

    debug_logger.log(std::format("Trying to send a packet to {}.\n",
                                 stringify_ip(actual_result.target)));

    if (connection_type == INET_STREAM) {
      auto connect_result = connect(skt, destination, destination_len);
      if (connect_result < 0) {
        error_logger.log(std::format(
            "Error occurred sending data: could not connect the socket: {}\n",
            strerror(errno)));
        close(skt);
        return -1;
      }
      if (write(skt, actual_result.body.data, actual_result.body.len) < 0) {
        error_logger.log(std::format("Error occurred sending data: could not "
                                     "write the body of the packet: {}\n",
                                     strerror(errno)));
      };
    } else if (connection_type == INET_DGRAM) {
      if (!coalesce_extensions(&actual_result.header_extensions,
                               IPV6_HOPOPTS)) {
        error_logger.log("Error occurred coalescing hop-by-hop options.\n");
        close(skt);
        return -1;
      }

      struct msghdr msg {};
      struct iovec iov {};

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
          debug_logger.log(
              std::format("extension_header_len: {}\n", extension_header_len));

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

      int write_result = sendmsg(skt, &msg, 0);

      if (write_result < 0) {
        error_logger.log(std::format(
            "Error occurred sending data: could not write to the socket: {}\n",
            strerror(errno)));
        close(skt);
        return -1;
      }

    } else {
      error_logger.log(
          std::format("Error occurred sending data: the destination address "
                      "had an invalid stream type.\n",
                      strerror(errno)));
    }

    // TODO: Cleanup the allocations nested in the packet.

    close(skt);

    return 0;
  }

  std::cerr << std::format(
      "An error occurred processing the packet pipeline: {}\n",
      std::get<std::string>(maybe_result));

  return 1;
}