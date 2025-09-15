#include "packetline/pipeline.hpp"
#include "api/plugin.h"
#include "packetline/logger.hpp"

#include <ranges>

bool Pipeline::parse(const char **to_parse, Plugins &&plugins) {

  size_t pipeline_count{1};

  std::vector<std::string_view> args{};
  for (size_t i = 0; to_parse[i] != nullptr; i++) {
    args.push_back(to_parse[i]);
  }

  for (const auto pipeline_args :
       std::views::split(args, std::string_view("=>"))) {

    // Every command must be longer than 1 element (the plugin name is
    // required, of course!).
    if (pipeline_args.empty()) {
      m_parse_errors.push_back(std::format(
          "Empty pipeline configurations are invalid (pipeline #{})",
          pipeline_count));
      return false;
    }

    const auto plugin_name = pipeline_args.front();
    Logger::ActiveLogger()->log(Logger::DEBUG,
                                std::format("Plugin name: {}", plugin_name));

    std::vector<std::string> args{std::next(pipeline_args.begin()),
                                  pipeline_args.end()};

    for (auto i = 0; i < args.size(); i++) {
      Logger::ActiveLogger()->log(
          Logger::DEBUG,
          std::format("Plugin {}'s arg #{}: {}", plugin_name, i + 1, args[i]));
    }

    auto maybe_plugin = plugins.plugin_by_name(plugin_name);

    if (maybe_plugin.has_value()) {
      auto plugin = *maybe_plugin;
      std::vector<const char *> argps{};
      std::transform(args.cbegin(), args.cend(), std::back_inserter(argps),
                     [&](auto &element) { return element.c_str(); });
      configuration_result_t invocation_configuration_result =
          plugin.generate_configuration(argps.size(), argps.data());

      if (!invocation_configuration_result.errstr) {
        m_invocations.invocations.push_back(Invocation{
            .plugin = *maybe_plugin,
            .args = args,
            .cookie = invocation_configuration_result.configuration_cookie});
      } else {
        m_parse_errors.push_back(std::format(
            "Error configuring plugin {} (pipeline position #{}): {}",
            plugin_name, pipeline_count,
            invocation_configuration_result.errstr));
      }
    } else {
      m_parse_errors.push_back(
          std::format("Cannot find plugin for {} (pipeline #{})", plugin_name,
                      pipeline_count));
    }

    pipeline_count++;
  }
  return true;
}
