#ifndef _USAGE_HPP
#define _USAGE_HPP

#include "packetline/pipeline.hpp"
#include <packetline/plugin.hpp>

class Usage {
public:
  std::ostream &usage(std::ostream &os, const char *program, Pipeline &&pipeline);
};
#endif