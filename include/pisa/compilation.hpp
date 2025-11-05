#ifndef _COMPILATION_HPP
#define _COMPILATION_HPP

#include "lib/pipeline.hpp"
#include "pisa/pisa.h"

#include <string>
#include <sys/socket.h>

struct CompilationResult {
  bool success{false};
  std::string error{};
  pisa_program_t *program{};
  const Pipeline *pipeline;
  packet_t packet;

  static CompilationResult Success(pisa_program_t *program, const Pipeline *pipeline) {
    return CompilationResult{.success = true, .error = "", .program = program, .pipeline = pipeline};
  }
  static CompilationResult Failure(std::string error, pisa_program_t *program = nullptr) {
    return CompilationResult{
        .success = false, .error = error, .program = program};
  }

  ~CompilationResult() {
    if (packet.all.data != nullptr) {
      free(packet.all.data);
      packet.ip.data = nullptr;
      packet.ip.len = 0;
      packet.transport.data = nullptr;
      packet.transport.len = 0;
      packet.ip_options.data = nullptr;
      packet.ip_options.len = 0;
      packet.body.data = nullptr;
      packet.body.len = 0;
    }
    pisa_program_release(program);
  }
};

#endif