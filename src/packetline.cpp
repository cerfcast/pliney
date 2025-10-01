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
#include "packetline/executors.hpp"
#include "packetline/logger.hpp"
#include "packetline/pipeline.hpp"

#include <unistd.h>

#include <errno.h>

extern int errno;

int main(int argc, const char **argv) {
  auto plugin_path = std::filesystem::path("./build");
  auto plugins = PluginDir{plugin_path};
  auto loaded_plugins = plugins.plugins();

  uint8_t connection_type = INET_STREAM;

  if (loaded_plugins.empty()) {
    std::cerr << "No plugins loaded.\n";
    return 1;
  }

  Logger::Level initial_logger_level{Logger::ERROR};

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
          std::cerr << std::format("Invalid connection type given: {}\n",
                                   argv[pliney_arg_idx]);
          return 1;
        }
        continue;
      }
      if (arg == "log") {
        HAS_ANOTHER_ARG;
        if (!Cli::parse_logger_level(argv[pliney_arg_idx],
                                     initial_logger_level)) {
          std::cerr << std::format("Invalid connection debug level given: {}\n",
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

  auto logger = Logger::ActiveLogger();
  // Now that the user had a chance to configure their preferred log level,
  // let's set it.
  logger->set_level(initial_logger_level);

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
  auto maybe_result = executor.execute(pipeline);

  if (std::holds_alternative<packet_t>(maybe_result)) {
    auto actual_result = std::get<packet_t>(maybe_result);
    auto skt = ip_to_socket(actual_result.target, connection_type);

    if (skt < 0) {
      std::cerr << std::format(
          "Error occurred sending data: could not open the socket: \n",
          strerror(errno));
      return -1;
    }

    auto netexec = CliNetworkExecutor();
    if (!netexec.execute(skt, connection_type, actual_result)) {
      std::cerr << "Error occurred executing the network connection.\n";
    } else {
      Logger::ActiveLogger()->log(Logger::DEBUG,
                                  "Execution of network connection succeeded.");
    }

    free_extensions(actual_result.header_extensions);

    auto cleanup_result = (pipeline.cleanup());
    if (cleanup_result) {
      std::cerr << std::format(
          "Error occurred cleaning up the plugins used in the pipeline: {}\n",
          *cleanup_result);
    }

    return 0;
  }

  std::cerr << std::format(
      "An error occurred processing the packet pipeline: {}\n",
      std::get<std::string>(maybe_result));

  return 1;
}