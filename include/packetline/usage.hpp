#ifndef __PLINEY_USAGE_HPP
#define __PLINEY_USAGE_HPP

#include <iosfwd>

class Pipeline;

class Usage {
public:
  std::ostream &usage(std::ostream &os, const char *program, Pipeline &&pipeline);
};
#endif