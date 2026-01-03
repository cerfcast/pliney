#include "lib/logger.hpp"
#include <format>
#include <iostream>

extern "C" {
int plugin_debug_level = DEBUG_LEVEL;
}

void LoggerImpl::log(std::string_view v) {
  std::cout << std::format("{}: {}\n", m_prefix, v);
}
