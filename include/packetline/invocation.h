#ifndef _INVOCATION_H
#define _INVOCATION_H

#include "packetline/plugin.h"
#include <string>
#include <vector>

class Invocation {
public:
  Plugin plugin;
  std::vector<std::string> args;
  void *cookie{nullptr};
  unsigned int index;
  bool operator!=(const Invocation &other) const {
    return plugin.name() != other.plugin.name() || index != other.index;
  }
};

class Invocations {
public:
  std::vector<Invocation> invocations;
};

#endif