#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <format>
#include <netinet/in.h>
#include <numeric>
#include <optional>
#include <sys/socket.h>
#include <variant>

#include "packetline/logger.hpp"
#include "packetline/pipeline.hpp"

bool configured = false;
std::optional<Pipeline> maybe_pipeline{};

__attribute__((constructor)) void pliney_initialize() {

  // TODO: Check that pliney is not already initialized, before
  // initializing again.

  printf("About to initialize plineyi\n");

  std::string pliney_plugin_path{"./build"};
  char *user_plugin_path = getenv("PLINEY_PLUGIN_PATH");
  if (user_plugin_path) {
    pliney_plugin_path = user_plugin_path;
  }

  auto logger = Logger::ActiveLogger();
  logger->set_level(Logger::TRACE);

  auto plugin_path = std::filesystem::path(pliney_plugin_path);
  auto plugins = PluginDir{plugin_path};
  auto loaded_plugins_result = plugins.plugins();

  if (std::holds_alternative<std::string>(loaded_plugins_result)) {
    Logger::ActiveLogger()->log(
        Logger::ERROR,
        std::format("Could not load plugins: {}",
                    std::get<std::string>(loaded_plugins_result)));
    configured = false;
    return;
  }

  auto loaded_plugins = std::get<Plugins>(loaded_plugins_result);
  if (!loaded_plugins.count()) {
    Logger::ActiveLogger()->log(Logger::ERROR, "No plugins loaded.");
    configured = false;
    return;
  }

  char *user_pipeline = getenv("PLINEY_PIPELINE");

  if (user_pipeline) {
    Pipeline pipeline{user_pipeline, std::move(loaded_plugins)};

    if (pipeline.ok()) {
      maybe_pipeline = std::move(pipeline);
    } else {
      auto pipeline_errs = std::accumulate(
          pipeline.error_begin(), pipeline.error_end(), std::string{},
          [](const std::string existing, const std::string next) {
            if (existing.length()) {
              return existing + "; " + next;
            }
            return next;
          });
      Logger::ActiveLogger()->log(
          Logger::ERROR,
          std::format("Error occurred configuring pipeline: {}\n",
                      pipeline_errs));
      return;
    }
  } else {
    Logger::ActiveLogger()->log(Logger::WARN, "No pliney pipeline found.");
  }
  configured = true;
}

__attribute__((destructor)) void pliney_deinitialize() {
  Logger::ActiveLogger()->log(
      Logger::ERROR, std::format("Pliney plugins cleaned up successfully."));
}
