#ifndef _PACKETLINE_H
#define _PACKETLINE_H

#include "plugin.h"
#include <string>
#include <variant>

using maybe_generate_result_t = std::variant<generate_result_t, std::string>;

#endif