#ifndef __PLINEY_LOGGER_HPP
#define __PLINEY_LOGGER_HPP

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#include "pisa/utils.h"
#include "lib/safety.hpp"

extern "C" {
  extern int plugin_debug_level;
}

class Logger {
public:
  enum Level {
    ERROR,
    WARN,
    DEBUG,
    TRACE,
    MAX,
  };

  class LoggerImpl {
  public:
    LoggerImpl(std::string prefix): m_prefix(prefix) {}
    void log(std::string_view v);
  private:
    std::string m_prefix;
  };

  static Logger &ActiveLogger() {
    static auto  active_logger{Logger(Level::ERROR)};

    return active_logger;
  }

  void set_level(Level l) {
    m_level = l;
    int plugin_debug = 0;

    if (l == DEBUG) {
      plugin_debug_level = DEBUG_LEVEL;
    } else if (l == WARN) {
      plugin_debug_level = WARN_LEVEL;
    } else if (l == TRACE) {
      plugin_debug_level = TRACE_LEVEL;
    } else if (l == ERROR) {
      plugin_debug_level = ERROR_LEVEL;
    }

  }

  void log(Level l, std::string_view msg) {
    if (l > m_level) {
      return;
    }

    m_active_logger[l]->log(msg);
  }

  Logger(Logger &&) = delete;
  Logger(const Logger &) = delete;
  Logger &operator=(const Logger &) = delete;
  Logger &operator=(Logger &&) = delete;

private:
  Logger(Level level): m_level(level), m_active_logger() {
    for (uint8_t level = Level::ERROR; level < Level::MAX; level++) {
      m_active_logger[level] = std::make_shared<LoggerImpl>(LevelString(static_cast<Level>(level)));
    }
  }

  ~Logger() {
    for (uint8_t level = Level::ERROR; level < Level::MAX; level++) {
      m_active_logger[level].reset();
    }
  }

  Level m_level;
  std::array<std::shared_ptr<LoggerImpl>, Level::MAX> m_active_logger;

  std::string LevelString(Logger::Level l) {
    if (l == ERROR) {
      return "ERROR";
    } else if (l == WARN) {
      return "WARN";
    } else if (l == DEBUG) {
      return "DEBUG";
    } else if (l == TRACE) {
      return "TRACE";
    }
    PLINEY_UNREACHABLE;
  }

};

#endif