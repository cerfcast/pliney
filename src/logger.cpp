#include "packetline/logger.hpp"
#include "api/utils.h"
#include <iostream>

extern "C" {
int plugin_debug_level = DEBUG_LEVEL;
}

void LoggerImpl::log(std::string_view v) { std::cout << "Debug: " << v; }

void Logger::log(std::string_view v) { return m_active_logger->log(v); }