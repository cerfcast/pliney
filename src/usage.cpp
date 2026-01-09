#include <packetline/usage.hpp>
#include <format>
#include <ostream>
#include <string>

#include "lib/pipeline.hpp"

std::ostream &Usage::usage(std::ostream &os, const char *program,
                           Pipeline &&pipeline) {
  os << std::format("{} Usage:\n", program);
  os << std::format("{} [OPTIONS] [ \\!\\> [<PLUGIN_INVOCATION> =\\>]\n",
                    program);
  os << std::format("\n");
  // clang-format off
  os << std::format("Using pliney involves writing a pipeline that will generate (a) packet(s)\n"
                    "for the network. Pipelines begin with a \\!\\> and are composed of uses of\n"
                    "plugins, separated by =\\>. General, optional OPTIONS can be given to\n"
                    "configure pliney before the pipeline. More information can be found in the\n"
                    "online documentation at XXXXX\n");
  os << std::format("\n");
  os << std::format("OPTIONS: \n");
  os << std::format("\t--type <dgram, stream>: To set whether pliney should send\n"
                    "\t\tthe packets the pipeline generates over a stream- or \n"
                    "\t\tdatagram-oriented socket.\n");
  os << std::format("\t--log <debug, warn, trace, error>: To set the log level.\n");
  os << std::format("\t--plugin-path PATH_NAME: Filesystem path where pliney should\n"
                    "\t\tlook for plugins\n");
  // clang-format on
  os << std::format("\n");
  os << std::format("PLUGIN_INVOCATION:\n");
  os << std::format("\t<PLUGIN_NAME> [plugin options ... see below]\n");
  os << std::format("\n");
  os << "Plugin Usage:" << "\n";
  os << pipeline.usage() << "\n";
  return os;
}