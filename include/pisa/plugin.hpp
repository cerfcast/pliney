#ifndef _PACKETLINE_PLUGIN_H
#define _PACKETLINE_PLUGIN_H

#include "pisa/pisa.h"
#include "pisa/plugin.h"
#include "packetline/packetline.hpp"

#include <filesystem>
#include <optional>
#include <vector>

typedef std::optional<std::string> plugin_cleanup_result_tt;

class Plugin {
public:
  explicit Plugin(std::filesystem::path path) : m_path(path), m_name(), info() {}

  bool load();
  plugin_cleanup_result_tt cleanup(void *);

  configuration_result_t generate_configuration(int argc, const char **args) {
    return this->info.configurator(argc, args);
  }

  std::string name() const { return m_name; }

  std::string usage() const;
  std::string params() const;

  result_generate_result_tt generate(pisa_program_t *program, void *cookie) const;

private:
  std::filesystem::path m_path;
  std::string m_name;
  plugin_t info;
};

class Plugins {

public:
  Plugins(std::vector<Plugin> &&plugins) : m_plugins(plugins) {}

  std::optional<Plugin> plugin_by_name(const std::string_view &plugin_name);

  std::string usage() const;

  size_t count() const;

private:
  std::vector<Plugin> m_plugins;
};

class PluginDir {
public:
  explicit PluginDir(std::filesystem::path p) : m_path(p) {}

  std::variant<Plugins, std::string> plugins();

private:
  std::filesystem::path m_path;
};


#endif