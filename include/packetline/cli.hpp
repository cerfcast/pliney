#ifndef _CLI_HPP
#define _CLI_HPP

#include "lib/logger.hpp"
#include "packetline/constants.hpp"
#include <cstddef>

class Cli {
public:
  static bool find_pipeline_start(size_t argc, const char **args,
                                  size_t *position);
  static bool parse_logger_level(const char *maybe_logger_level,
                                    Logger::Level &level);
};
#endif