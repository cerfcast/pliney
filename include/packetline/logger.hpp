#ifndef _LOGGER_H
#define _LOGGER_H

#include <memory>

class LoggerImpl {
public:
  void log(std::string_view v);
};

class Logger {
public:
  enum Level {
    ERROR,
    WARN,
    DEBUG,
  };

  static Logger active_logger(Level level) {
    static auto d_logger = std::make_shared<LoggerImpl>();

    return Logger(d_logger);
  }


  void log(std::string_view v);

private:
  explicit Logger(std::shared_ptr<LoggerImpl> impl)
      : m_active_logger(std::move(impl)) {}
  std::shared_ptr<LoggerImpl> m_active_logger;
};

#endif