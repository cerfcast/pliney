#ifndef _PACKETLINE_PLUGIN_H
#define _PACKETLINE_PLUGIN_H

#include "api/plugin.h"
#include "packetline/packetline.hpp"

#include <filesystem>
#include <vector>

class Plugin {
public:
  explicit Plugin(std::filesystem::path path) : m_path(path) {}

  bool load();

  configuration_result_t generate_configuration(int argc, const char **args) {
    return this->info.configurator(argc, args);
  }

  std::string name() const { return m_name; }

  maybe_generate_result_t generate(packet_t *packet, void *cookie) const;

private:
  std::filesystem::path m_path;
  std::string m_name;
  plugin_t info;
};

class Plugins {

public:
  Plugins(std::vector<Plugin> &&plugins) : m_plugins(plugins) {}

  std::optional<Plugin> plugin_by_name(const std::string_view &plugin_name);

private:
  std::vector<Plugin> m_plugins;
};

class PluginDir {
public:
  explicit PluginDir(std::filesystem::path p) : m_path(p) {}

  std::vector<Plugin> plugins();

private:
  std::filesystem::path m_path;
};


#endif