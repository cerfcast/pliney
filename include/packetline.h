#ifndef _PACKETLINE_H
#define _PACKETLINE_H

#include <variant>
#include "plugin.h"
#include <string>

using maybe_generate_result_t = std::variant<generate_result_t, std::string>;

std::string stringify_ip(ip_addr_t addr);

#endif