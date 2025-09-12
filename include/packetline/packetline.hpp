#ifndef _PACKETLINE_H
#define _PACKETLINE_H

#include <string>
#include <variant>
#include "api/plugin.h"

class Invocations;

using maybe_packet_t = std::variant<packet_t, std::string>;
using maybe_generate_result_t = std::variant<generate_result_t, std::string>;
using maybe_invocation_t = std::variant<Invocations, std::string>;

#endif