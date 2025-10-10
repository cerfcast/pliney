#include "packetline/cli.hpp"
#include "api/plugin.h"
#include "packetline/logger.hpp"

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
  }
  return false;
}

bool Cli::parse_connection_type(const char *maybe_stream_type_raw,
                                uint8_t &type) {
  std::string maybe_stream_type{maybe_stream_type_raw};

  bool is_valid{true};
  if (maybe_stream_type == "stream") {
    type = INET_STREAM;
  } else if (maybe_stream_type == "dgram") {
    type = INET_DGRAM;
  } else {
    is_valid = false;
  }
  return is_valid;
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