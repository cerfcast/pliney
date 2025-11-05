#ifndef _USAGE_HPP
#define _USAGE_HPP

#include "lib/pipeline.hpp"

class Usage {
public:
  std::ostream &usage(std::ostream &os, const char *program, Pipeline &&pipeline);
};
#endif