#ifndef _PIPELINE_H
#define _PIPELINE_H

#include <vector>
#include "packetline/plugin.hpp"
#include "packetline/invocation.hpp"

class Pipeline {
public:

  Pipeline(const char *source, Plugins &&plugins);
  Pipeline(const char **source, Plugins &&plugins);

  class Iterator {
  public:
    using difference_type = std::vector<Invocation>::difference_type;
    using iterator_category = std::forward_iterator_tag;
    using value_type = const Invocation &;

    const Invocation &operator*() const { return *m_it; }

    void operator++() { m_it++; }

    Iterator(std::vector<Invocation>::const_iterator &&it) : m_it{it} {}

    bool operator!=(const Iterator &other) { return m_it != other.m_it; }

  private:
    std::vector<Invocation>::const_iterator m_it;
  };

  class ErrorIterator {
  public:
    using difference_type = std::vector<Invocation>::difference_type;
    using iterator_category = std::forward_iterator_tag;
    using value_type = const std::string &;

    const std::string &operator*() const { return *m_it; }

    void operator++() { m_it++; }

    ErrorIterator(std::vector<std::string>::const_iterator &&it) : m_it{it} {}

    bool operator!=(const ErrorIterator &other) { return m_it != other.m_it; }

  private:
    std::vector<std::string>::const_iterator m_it;
  };


  Iterator begin() const {
    return Iterator{std::move(m_invocations.invocations.begin())};
  }

  Iterator end() const {
    return Iterator{std::move(m_invocations.invocations.end())};
  }

  ErrorIterator error_begin() const {
    return ErrorIterator{std::move(m_parse_errors.begin())};
  }

  ErrorIterator error_end() const {
    return ErrorIterator{std::move(m_parse_errors.end())};
  }

  bool ok() const {
    return m_parse_errors.size() == 0;
  }

private:
  void parse(const std::vector<std::string_view> args, Plugins &&plugins);

private:
  std::string m_raw;
  bool m_parsed;
  Invocations m_invocations;
  std::vector<std::string> m_parse_errors;
};

#endif