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
    return this->m_generate_configurationer(argc, args);
  }

  std::string name() const { return m_name; }

  maybe_generate_result_t generate(ip_addr_t source_ip,
                                   ip_addr_t destination_ip, extensions_p header, body_p body,
                                   void *cookie) const;

private:
  std::filesystem::path m_path;
  std::string m_name;
  generate_t m_generator{nullptr};
  generate_configuration_t m_generate_configurationer{nullptr};
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