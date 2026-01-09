#ifndef __PLINEY_CLI_HPP
#define __PLINEY_CLI_HPP

#include <cstddef>

#include "lib/logger.hpp"
#include "packetline/constants.hpp"

class Cli {
public:
  static bool find_pipeline_start(size_t argc, const char **args,
                                  size_t *position);
  static bool parse_logger_level(const char *maybe_logger_level,
                                    Logger::Level &level);
};
#endif