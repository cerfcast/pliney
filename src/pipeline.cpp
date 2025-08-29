#include "packetline/pipeline.h"
#include "packetline/logger.h"

#include <ranges>

bool Pipeline::parse(const char **to_parse, Plugins &&plugins) {
  auto debug_logger = Logger::active_logger(Logger::Level::DEBUG);
  auto error_logger = Logger::active_logger(Logger::Level::ERROR);

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
    debug_logger.log(std::format("Plugin name: {}\n", plugin_name));

    std::vector<std::string> args{std::next(pipeline_args.begin()),
                                  pipeline_args.end()};

    for (auto i = 0; i < args.size(); i++) {
      debug_logger.log(std::format("Plugin {}'s arg #{}: {}\n", plugin_name,
                                   i + 1, args[i]));
    }

    auto maybe_plugin = plugins.plugin_by_name(plugin_name);

    if (maybe_plugin.has_value()) {
      auto plugin = *maybe_plugin;
      std::vector<const char *> argps{};
      std::transform(args.cbegin(), args.cend(), std::back_inserter(argps),
                     [&](auto &element) { return element.c_str(); });
      void *invocation_cookie = plugin.generate_configuration(argps.data());
      m_invocations.invocations.push_back(Invocation{
          .plugin = *maybe_plugin, .args = args, .cookie = invocation_cookie});
    } else {
      m_parse_errors.push_back(
          std::format("Cannot find plugin for {} (pipeline #{})", plugin_name,
                      pipeline_count));
    }

    pipeline_count++;
  }
  return true;
}
