#include <errno.h>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <iostream>
#include <memory>
#include <numeric>
#include <utility>
#include <optional>
#include <string>
#include <type_traits>
#include <variant>

#include "lib/logger.hpp"
#include "lib/pipeline.hpp"
#include "packetline/cli.hpp"
#include "packetline/runner.hpp"
#include "packetline/usage.hpp"
#include "pisa/compilation.hpp"
#include "pisa/compiler.hpp"
#include "pisa/pisa.h"
#include "pisa/plugin.hpp"

extern int errno;

int main(int argc, const char **argv) {

  CompilerBuilder pipeline_compiler_builder{};

  pipeline_compiler_builder.with_name("xdp", []() {
    return std::make_pair(std::make_unique<XdpCompiler>(),
                          std::make_unique<XdpRunner>());
  });
  pipeline_compiler_builder.with_name("cli", []() {
    return std::make_pair(std::make_unique<CliCompiler>(),
                          std::make_unique<CliRunner>());
  });
  pipeline_compiler_builder.with_name("fork", []() {
    return std::make_pair(std::make_unique<CliCompiler>(),
                          std::make_unique<ForkRunner>());
  });
  pipeline_compiler_builder.with_name("packet", []() {
    return std::make_pair(std::make_unique<CliCompiler>(),
                          std::make_unique<PacketSenderRunner>());
  });

  std::optional<std::pair<std::unique_ptr<Compiler>, std::unique_ptr<Runner>>>
      maybe_pipeline_compiler_runner{};

  std::string runner_name{"cli"};

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
      if (arg == "log") {
        HAS_ANOTHER_ARG;
        if (!Cli::parse_logger_level(argv[pliney_arg_idx], cli_logger_level)) {
          std::cerr << std::format("Invalid connection debug level given: {}\n",
                                   argv[pliney_arg_idx]);
          return 1;
        }
        continue;
      }
      // In test mode, add a test runner!
      if (arg == "test") {
        pipeline_compiler_builder.with_name("test", []() {
          return std::make_pair(std::make_unique<CliCompiler>(),
                                std::make_unique<TestSenderRunner>());
        });
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
      if (arg == "runner-name") {
        HAS_ANOTHER_ARG;
        runner_name = argv[pliney_arg_idx];

        auto pcr_find_lookup_result =
            pipeline_compiler_builder.by_name(runner_name);
        if (std::holds_alternative<std::string>(pcr_find_lookup_result)) {
          std::cerr << std::format(
              "No pipeline executor named {} is registered.",
              std::get<std::string>(pcr_find_lookup_result));
          return 1;
        }

        auto [pipeline_compiler, pipeline_runner] = std::move(
            std::get<
                std::pair<std::unique_ptr<Compiler>, std::unique_ptr<Runner>>>(
                pcr_find_lookup_result));

        // Now, let's try to configure it!
        auto runner_command_line{Commandline{argv + pliney_arg_idx + 1}};
        auto configure_result =
            pipeline_runner->configure(runner_command_line.get());
        if (std::holds_alternative<std::string>(configure_result)) {
          std::cerr << std::format("Pipeline runner configuration failed: {}\n",
                                   std::get<std::string>(configure_result));
          return 1;
        }

        auto args_consumed{std::get<size_t>(configure_result)};

        pliney_arg_idx += args_consumed;

        maybe_pipeline_compiler_runner = std::move(std::make_pair(
            std::move(pipeline_compiler), std::move(pipeline_runner)));

        continue;
      }
    }
    std::cerr << std::format("Unrecognized argument: {}\n",
                             argv[pliney_arg_idx]);
    should_show_help = true;
    break;
  }

  // Now that the user had a chance to configure their preferred log level,
  // let's set it and use it.
  Logger::ActiveLogger().set_level(cli_logger_level);

  // If there is no maybe_pipeline_compiler_runner, then we go with the default.
  if (!maybe_pipeline_compiler_runner) {
    Logger::ActiveLogger().log(Logger::DEBUG, "Using the default runner.");
    maybe_pipeline_compiler_runner = std::make_pair(
        std::make_unique<CliCompiler>(), std::make_unique<CliRunner>());
  }

  auto pipeline_compiler_runner = std::move(*maybe_pipeline_compiler_runner);

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

  Pipeline pipeline{argv + pipeline_start, std::move(loaded_plugins)};

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

  auto pipeline_compiler = std::move(std::get<0>(pipeline_compiler_runner));
  auto pipeline_runner = std::move(std::get<1>(pipeline_compiler_runner));

  auto pisa_program =
      std::unique_ptr<pisa_program_t, PisaProgramDeleter>{pisa_program_new()};
  auto compilation_result =
      pipeline_compiler->compile(std::move(pisa_program), &pipeline);

  if (compilation_result.success) {

    auto runner_result = pipeline_runner->execute(compilation_result);

    if (!runner_result) {
      std::cerr << std::format(
          "Error occurred executing the network connection: {}\n",
          compilation_result.error);
      return 1;
    } else {
      Logger::ActiveLogger().log(Logger::DEBUG,
                                 "Execution of network connection succeeded.");
    }

    return 0;
  }

  std::cerr << std::format(
      "An error occurred compiling the packet pipeline: {}\n",
      compilation_result.error);

  return 1;
}