#ifndef __PLINEY_COMPILATION_HPP
#define __PLINEY_COMPILATION_HPP

#include "lib/pipeline.hpp"
#include "pisa/pisa.h"

#include <memory>
#include <string>
#include <sys/socket.h>


struct PisaProgramDeleter {
  void operator()(pisa_program_t *to_delete){
    pisa_program_release(to_delete);
  }
};

using unique_pisa_program_t = std::unique_ptr<pisa_program_t, PisaProgramDeleter>;

struct Compilation {
  bool success{false};
  std::string error{};
  unique_pisa_program_t program{};
  const Pipeline *pipeline;
  packet_t packet;

  static Compilation Success(unique_pisa_program_t program, const Pipeline *pipeline) {
    return Compilation{.success = true, .error = "", .program = std::move(program), .pipeline = pipeline};
  }
  static Compilation Failure(std::string error, unique_pisa_program_t program) {
    return Compilation{
        .success = false, .error = error, .program = std::move(program)};
  }

  explicit operator bool() const {
    return success && program;
  }

  ~Compilation() {
    if (packet.all.data != nullptr) {
      free(packet.all.data);
      packet.ip.data = nullptr;
      packet.ip.len = 0;
      packet.transport.data = nullptr;
      packet.transport.len = 0;
      packet.ip_opts_exts.data = nullptr;
      packet.ip_opts_exts.len = 0;
      packet.body.data = nullptr;
      packet.body.len = 0;
    }
  }
};

#endif