#ifndef __PLINEY_SAFETY_HPP
#define __PLINEY_SAFETY_HPP

#include <exception>
struct PlineyUnreachable : public std::exception {};

#ifdef UNREACHABLE_ASSERT
#define PLINEY_UNREACHABLE { throw PlineyUnreachable{}; }
#else
#include <utility>
#define PLINEY_UNREACHABLE std::unreachable();
#endif

#endif