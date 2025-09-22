#include "packetline/pipeline.hpp"
#include "api/plugin.h"
#include "packetline/logger.hpp"

#include <algorithm>
#include <ranges>
#include <string_view>

template <typename W>
class Trimit : public std::ranges::range_adaptor_closure<Trimit<W>> {
  const W m_of_what;

  template <typename T> static std::string trim(T &&to_trim, W of_what) {
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

Pipeline::Pipeline(const char *source, Plugins &&plugins) {
  std::vector<std::string> args{};
  std::vector<std::string_view> argv{};

  std::ranges::for_each(
      std::views::split(std::string_view(source), std::string_view(" ")) |
          std::views::transform(
              [](const auto x) { return std::string_view(x); }) |
          Trimit(' '),
      [&args](const auto x) { args.push_back((x)); });

  std::ranges::for_each(args, [&argv](const auto &x) { argv.push_back(x); });

  parse(argv, std::move(plugins));
}

Pipeline::Pipeline(const char **source, Plugins &&plugins) {
  std::vector<std::string_view> args{};
  for (size_t i = 0; source[i] != nullptr; i++) {
    args.push_back(source[i]);
  }

  Pipeline::parse(args, std::move(plugins));
}

void Pipeline::parse(const std::vector<std::string_view> args,
                     Plugins &&plugins) {
  size_t pipeline_count{1};

  for (const auto pipeline_args :
       std::views::split(args, std::string_view("=>"))) {

    // Every command must be longer than 1 element (the plugin name is
    // required, of course!).
    if (pipeline_args.empty()) {
      m_parse_errors.push_back(std::format(
          "Empty pipeline configurations are invalid (pipeline #{})",
          pipeline_count));
      return;
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
}
