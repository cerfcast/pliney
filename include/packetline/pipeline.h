#ifndef _PIPELINE_H
#define _PIPELINE_H

#include <vector>
#include "packetline/plugin.h"
#include "packetline/invocation.h"

class Pipeline {
public:
  explicit Pipeline(const char **source, Plugins &&plugins) {
    parse(source, std::move(plugins));
  };

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

  Iterator begin() const {
    return Iterator{std::move(m_invocations.invocations.begin())};
  }

  Iterator end() const {
    return Iterator{std::move(m_invocations.invocations.end())};
  }

private:
  bool parse(const char **to_parse, Plugins &&plugins);

private:
  std::string m_raw;
  bool m_parsed;
  Invocations m_invocations;
  std::vector<std::string> m_parse_errors;
};

#endif