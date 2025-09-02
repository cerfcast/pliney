#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <filesystem>
#include <format>
#include <iostream>
#include <netinet/in.h>
#include <numeric>
#include <sys/socket.h>
#include <variant>
#include <vector>

#include "api/plugin.h"
#include "api/utils.h"
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
  virtual maybe_generate_result_t execute(Pipeline &&plugins) = 0;
};

class SerialPipelineExecutor : public PipelineExecutor {
public:
  maybe_generate_result_t execute(Pipeline &&pipeline) override {

    ip_addr_t target_ip{.stream = INET_STREAM};
    ip_addr_t source_ip{.stream = INET_STREAM};
    body_p body{};

    auto debug_logger = Logger::active_logger(Logger::DEBUG);

    for (auto invocation : pipeline) {

      auto result = invocation.plugin.generate(source_ip, target_ip, body,
                                               invocation.cookie);

      if (std::holds_alternative<generate_result_t>(result)) {
        debug_logger.log(std::format("Got a result from '{}' plugin!\n",
                                     invocation.plugin.name()));
        generate_result_t x = std::get<generate_result_t>(result);
        target_ip = x.destination;
        body = x.body;
      } else {
        std::cout << std::format("There was an error: {}\n",
                                 std::get<std::string>(result));
        return std::get<std::string>(result);
      }
    }

    return generate_result_t{target_ip, source_ip, body};
  }
};

int main(int argc, const char **argv) {
  auto plugin_path = std::filesystem::path("./build");
  auto plugins = PluginDir{plugin_path};
  auto loaded_plugins = plugins.plugins();

  if (loaded_plugins.empty()) {
    std::cerr << "No plugins loaded.\n";
    return 1;
  }

  auto pipeline = Pipeline{argv + 1, std::move(loaded_plugins)};

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

  if (std::holds_alternative<generate_result_t>(maybe_result)) {

    auto actual_result = std::get<generate_result_t>(maybe_result);
    auto skt = ip_to_socket(actual_result.destination);

    if (skt < 0) {
      std::cerr << std::format(
          "Error occurred sending data: could not open the socket: \n",
          strerror(errno));
      return -1;
    }

    struct sockaddr *destination = nullptr;
    int destination_len =
        ip_to_sockaddr(actual_result.destination, &destination);
    if (destination_len < 0) {
      std::cerr << "Error occurred converting generated destination into "
                   "system-compatible destination.\n";
      close(skt);
      return -1;
    }

    debug_logger.log(std::format("Trying to send a packet to {}.\n",
                                 stringify_ip(actual_result.destination)));

    if (actual_result.destination.stream == INET_STREAM) {

      auto connect_result = connect(skt, destination, destination_len);
      if (connect_result < 0) {
        error_logger.log(std::format(
            "Error occurred sending data: could not connect the socket: \n",
            strerror(errno)));
        close(skt);
        return -1;
      }
    } else if (actual_result.destination.stream == INET_DGRAM) {
      int write_result =
          sendto(skt, actual_result.body.data, actual_result.body.len, 0,
                 destination, destination_len);

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

    close(skt);

    return 0;
  }

  std::cerr << std::format(
      "An error occurred processing the packet pipeline: {}\n",
      std::get<std::string>(maybe_result));

  return 1;
}