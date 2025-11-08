#include "packetline/cli.hpp"
#include "lib/logger.hpp"

#include <ranges>
#include <string>

bool Cli::find_pipeline_start(size_t argc, const char **args,
                              size_t *position) {
  *position = 0;

  auto result = std::ranges::find_if(
      std::ranges::subrange(args, args + argc) | std::views::enumerate,
      [](const auto p) {
        if (std::get<1>(p) == std::string{"!>"}) {
          return true;
        }
        return false;
      });

  if (std::get<0>(*result) != argc) {
    *position = std::get<0>(*result);
    return true;
  } else {
    *position = argc;
  }
  return false;
}

bool Cli::parse_logger_level(const char *maybe_logger_level_raw,
                             Logger::Level &level) {
  std::string maybe_logger_level{maybe_logger_level_raw};
  if (maybe_logger_level == "debug") {
    level = Logger::DEBUG;
    return true;
  } else if (maybe_logger_level == "warn") {
    level = Logger::WARN;
    return true;
  } else if (maybe_logger_level == "trace") {
    level = Logger::TRACE;
    return true;
  } else if (maybe_logger_level == "error") {
    level = Logger::ERROR;
    return true;
  }
  return false;
}