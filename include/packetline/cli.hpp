#ifndef _OPTION_HPP
#define _OPTION_HPP

#include "packetline/logger.hpp"
#include <cstddef>
#include <cstdint>

class Cli {
public:
  static bool find_pipeline_start(size_t argc, const char **args,
                                  size_t *position);
  static bool parse_connection_type(const char *maybe_stream_type,
                                    uint8_t &type);
  static bool parse_logger_level(const char *maybe_logger_level,
                                    Logger::Level &level);
};
#endif