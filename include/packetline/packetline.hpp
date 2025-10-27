#ifndef _PACKETLINE_H
#define _PACKETLINE_H

#include <string>
#include <variant>
#include "api/plugin.h"

class Invocations;

using result_pipeline_tt = std::variant<packet_t, std::string>;
using result_generate_result_tt = std::variant<generate_result_t, std::string>;
using result_invocation_tt = std::variant<Invocations, std::string>;

#endif