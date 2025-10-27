#ifndef _LOGGER_H
#define _LOGGER_H

#include "api/utils.h"
#include <array>
#include <memory>
#include <string_view>

extern "C" {
  extern int plugin_debug_level;
}

class LoggerImpl {
public:
  LoggerImpl(std::string prefix): m_prefix(prefix) {}
  void log(std::string_view v);
private:
  std::string m_prefix;
};

class Logger {
public:
  enum Level {
    ERROR,
    WARN,
    DEBUG,
    TRACE,
    MAX,
  };

  static std::shared_ptr<Logger> ActiveLogger() {
    // Quite annoying.
    struct enable_access: public Logger {
      enable_access(Level level): Logger(std::forward<Level>(level)) {}
    };

    static auto  active_logger = std::make_shared<enable_access>(ERROR);

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

    // Lazy initialize the logger.
    if (!m_active_logger[l]) {
      m_active_logger[l] = std::make_shared<LoggerImpl>(LevelString(l));
    }

    m_active_logger[l]->log(msg);
  }

  void log(std::string_view v);

private:
  Logger(Level level): m_level(level), m_active_logger() {}
  Level m_level;
  std::array<std::shared_ptr<LoggerImpl>, Level::MAX> m_active_logger;

  std::string LevelString(Logger::Level l) {
    if (l == ERROR) {
      return "ERROR";
    } else if (l == DEBUG) {
      return "DEBUG";
    } else if (l == WARN) {
      return "WARN";
    }
    return "UNKNOWN";
  }

};

#endif