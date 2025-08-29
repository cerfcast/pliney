#include "packetline/logger.h"
#include <iostream>

void LoggerImpl::log(std::string_view v) { std::cout << "Debug: " << v; }

void Logger::log(std::string_view v) { return m_active_logger->log(v); }