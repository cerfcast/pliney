#include <arpa/inet.h>
#include <bits/types/struct_iovec.h>
#include <cstdio>
#include <cstdlib>
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
#include "packetline/cli.hpp"
#include "packetline/executors/pipeline.hpp"
#include "packetline/executors/result.hpp"
#include "packetline/logger.hpp"
#include "packetline/pipeline.hpp"
#include "packetline/plugin.hpp"
#include "packetline/usage.hpp"

#include <unistd.h>

#include <errno.h>

extern int errno;

int main(int argc, const char **argv) {

  PipelineExecutorBuilder pipeline_executor_builder{};

  pipeline_executor_builder.with_name(
      "xdp", []() { return std::make_unique<XdpPipelineExecutor>(); });
  pipeline_executor_builder.with_name("network", []() {
    return std::make_unique<NetworkSerialPipelineExecutor>();
  });
  std::string network_executor_builder_name{"network"};

  uint8_t cli_connection_type = INET_STREAM;
  Logger::Level cli_logger_level{Logger::ERROR};
  std::string cli_plugin_path{"./build"};

  char *plugin_path_env = nullptr;
  if ((plugin_path_env = getenv("PLINEY_PLUGIN_PATH"))) {
    cli_plugin_path = plugin_path_env;
  }

  // Determine where the pipeline starts ...
  size_t pipeline_start{0};
  auto pipeline_start_found =
      Cli::find_pipeline_start(argc, argv, &pipeline_start);

  auto should_show_help{false};

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
                                        cli_connection_type)) {
          std::cerr << std::format("Invalid connection type given: {}\n",
                                   argv[pliney_arg_idx]);
          return 1;
        }
        continue;
      }
      if (arg == "log") {
        HAS_ANOTHER_ARG;
        if (!Cli::parse_logger_level(argv[pliney_arg_idx], cli_logger_level)) {
          std::cerr << std::format("Invalid connection debug level given: {}\n",
                                   argv[pliney_arg_idx]);
          return 1;
        }
        continue;
      }
      if (arg == "plugin-path") {
        HAS_ANOTHER_ARG;
        cli_plugin_path = argv[pliney_arg_idx];
        continue;
      }
      if (arg == "help") {
        should_show_help = true;
        continue;
      }
      if (arg == "netexec-name") {
        HAS_ANOTHER_ARG;
        network_executor_builder_name = argv[pliney_arg_idx];
        continue;
      }
    }
    std::cerr << std::format("Unrecognized argument: {}\n",
                             argv[pliney_arg_idx]);
    should_show_help = true;
  }

  auto logger = Logger::ActiveLogger();
  // Now that the user had a chance to configure their preferred log level,
  // let's set it and use it.
  logger->set_level(cli_logger_level);

  auto maybe_pipeline_executor =
      pipeline_executor_builder.by_name(network_executor_builder_name);
  if (std::holds_alternative<std::string>(maybe_pipeline_executor)) {
    std::cerr << std::format("No pipeline executor named {} is registered.",
                             std::get<std::string>(maybe_pipeline_executor));
    return 1;
  }
  auto pipeline_exec = std::move(
      std::get<std::unique_ptr<PipelineExecutor>>(maybe_pipeline_executor));

  auto plugin_fs_path = std::filesystem::path(cli_plugin_path);
  auto plugins = PluginDir{plugin_fs_path};
  auto loaded_plugins_result = plugins.plugins();

  if (std::holds_alternative<std::string>(loaded_plugins_result)) {
    std::cerr << std::format("Could not open the given plugins directory: {}\n",
                             std::get<std::string>(loaded_plugins_result));
    return 1;
  }

  auto loaded_plugins = std::get<Plugins>(loaded_plugins_result);
  /*
  if (loaded_plugins.empty()) {
    std::cerr << "No plugins loaded.\n";
    return 1;
  }*/

  Pipeline pipeline{argv + pipeline_start + 1, std::move(loaded_plugins)};

  if (should_show_help) {
    Usage us{};
    us.usage(std::cout, argv[0], std::move(pipeline));
    return 1;
  }

  if (!pipeline_start_found) {
    std::cerr << "No pipeline found.\n";
    return 1;
  }

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

    Usage us{};
    us.usage(std::cout, argv[0], std::move(pipeline));

    return 1;
  }

  auto maybe_result = pipeline_exec->execute(
      packet_t{.transport = cli_connection_type}, pipeline);

  if (maybe_result.success && maybe_result.needs_network) {
    auto packet = *maybe_result.packet;
    auto netexec = CliResultExecutor();
    if (!netexec.execute(maybe_result)) {
      std::cerr << "Error occurred executing the network connection.\n";
      return 1;
    } else {
      Logger::ActiveLogger()->log(Logger::DEBUG,
                                  "Execution of network connection succeeded.");
    }

    free_extensions(packet.header_extensions);
    return 0;
  }

  std::cerr << std::format(
      "An error occurred processing the packet pipeline: {}\n",
      *maybe_result.error);

  return 1;
}