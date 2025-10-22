#include "api/native.h"
#include "api/plugin.h"
#include <fcntl.h>
#include <netinet/ip.h>
#include <pcap/dlt.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "api/utils.h"
#include "pcap/pcap.h"

char *plugin_name = "log";

typedef struct {
  pcap_t *libp;
  pcap_dumper_t *dumper;
  ip_addr_t default_addr;
  uint8_t default_transport;
} logp_cookie_t;

enum mode { OVERWRITE, APPEND };

configuration_result_t generate_configuration(int argc, const char **args) {
  configuration_result_t configuration_result = {.configuration_cookie = NULL,
                                                 .errstr = NULL};

  if (!argc) {
    char *err = (char *)calloc(255, sizeof(char));
    snprintf(err, 255, "pcap logging plugin got no arguments.");
    configuration_result.errstr = err;
    return configuration_result;
  }

  char pcaperr[PCAP_ERRBUF_SIZE] = {
      0,
  };

  // Determine if the user wanted to append or overwrite ...
  const char *filename = args[0];
  int mode = OVERWRITE;
  ip_addr_t default_addr;
  uint8_t default_transport;

  for (size_t arg = 0; arg < argc; arg++) {

#define HAS_ANOTHER_ARG                                                        \
  if (arg + 1 >= argc) {                                                       \
    char *err = (char *)calloc(255, sizeof(char));                             \
    snprintf(err, 255, "Missing argument for option %s", args[arg]);           \
    configuration_result.errstr = err;                                         \
    return configuration_result;                                               \
  } else {                                                                     \
    arg++;                                                                     \
  }

    if (!strcmp(args[arg], "-mode")) {
      HAS_ANOTHER_ARG;
      if (!strcmp(args[arg], "append")) {
        mode = APPEND;
      } else if (!strcmp(args[arg], "overwrite")) {
        mode = OVERWRITE;
      } else {
        char *err = (char *)calloc(255, sizeof(char));
        snprintf(
            err, 255,
            "Invalid overwrite/append configuration option (%s); values are "
            "append or overwrite",
            args[arg]);
        configuration_result.errstr = err;
        return configuration_result;
      }
    } else if ((!strcmp(args[arg], "-default-ip"))) {
      HAS_ANOTHER_ARG;
      if (ip_parse(args[arg], &default_addr) < 0) {
        char *err = (char *)calloc(255, sizeof(char));
        snprintf(
            err, 255,
            "Could not parse the IP address given as the default address (%s)",
            args[arg]);
        configuration_result.errstr = err;
        return configuration_result;
      }
    } else if ((!strcmp(args[arg], "-default-transport"))) {
      HAS_ANOTHER_ARG;
      if (!strcmp(args[arg], "dgram")) {
        default_transport = INET_DGRAM;
      } else if (!strcmp(args[arg], "stream")) {
        default_transport = INET_STREAM;
      } else {
        char *err = (char *)calloc(255, sizeof(char));
        snprintf(err, 255,
                 "Could not parse the IP address given as the default "
                 "transport (%s)",
                 args[arg]);
        configuration_result.errstr = err;
        return configuration_result;
      }
    } else {
      filename = args[arg];
      break;
    }
  }

  if (pcap_init(0, pcaperr)) {
    char *pcap_nice_err = (char *)calloc(255, sizeof(char));
    snprintf(pcap_nice_err, 255, "Could not initialize the pcap library: %s\n",
             pcaperr);
    configuration_result.errstr = pcap_nice_err;
    return configuration_result;
  }

  // Use RAW so that we can insert either IPv4 _or_ IPv6 packets.
  pcap_t *libp = pcap_open_dead(DLT_RAW, 1500);
  if (!libp) {
    char *pcap_nice_err = (char *)calloc(255, sizeof(char));
    snprintf(pcap_nice_err, 255, "Could not open a dead pcap.");
    configuration_result.errstr = pcap_nice_err;
    return configuration_result;
  }

  pcap_dumper_t *dumper = NULL;

  // Determine if the user wanted to append or overwrite ...
  if (mode == OVERWRITE) {
    dumper = pcap_dump_open(libp, filename);
  } else {
    dumper = pcap_dump_open_append(libp, filename);
  }

  if (!dumper) {
    char *pcap_nice_err = (char *)calloc(255, sizeof(char));
    snprintf(
        pcap_nice_err, 255,
        "Could not open the specified file for storing packet captures: %s",
        pcap_geterr(libp));
    configuration_result.errstr = pcap_nice_err;
    pcap_close(libp);
    return configuration_result;
  }

  logp_cookie_t *cookie = (logp_cookie_t *)calloc(1, sizeof(logp_cookie_t));

  cookie->dumper = dumper;
  cookie->libp = libp;
  cookie->default_addr = default_addr;
  cookie->default_transport = default_transport;

  configuration_result.configuration_cookie = (void *)cookie;

  return configuration_result;
}

generate_result_t generate(packet_t *packet, void *cookie) {
  generate_result_t result = {.success = true};

  if (cookie != NULL) {
    logp_cookie_t *lcookie = (logp_cookie_t *)cookie;

    size_t native_len = 1500;
    uint8_t native_packet[1500] = {
        0,
    };
    void *native_packet_p = &native_packet;
    bool used_default_ip = false;
    bool used_default_transport = false;

    if (!ip_set(packet->target)) {
      warn("No target IP set, using the default");
      packet->target = lcookie->default_addr;
      used_default_ip = true;
    }

    if (!packet->transport) {
      warn("No transport set, using the default");
      packet->transport = lcookie->default_transport;
      used_default_transport = true;
    }

    if (!to_native_packet(packet->transport, *packet, (void **)&native_packet_p,
                          &native_len)) {
      error("Could not convert to a native packet.\n");
      result.success = false;
      return result;
    }

    struct pcap_pkthdr hdr;
    hdr.caplen = native_len;
    hdr.len = hdr.caplen;
    hdr.ts.tv_sec = 0;
    hdr.ts.tv_usec = 0;

    pcap_dump((u_char *)lcookie->dumper, &hdr, (const u_char *)native_packet);
    pcap_dump_flush(lcookie->dumper);

    if (used_default_ip) {
      memset(&packet->target, 0, sizeof(ip_addr_t));
    }
    if (used_default_transport) {
      packet->transport = 0;
    }
  }

  return result;
}

cleanup_result_t cleanup(void *cookie) {
  cleanup_result_t result = {.success = true, .errstr = NULL};

  if (cookie != NULL) {
    logp_cookie_t *lcookie = (logp_cookie_t *)cookie;

    pcap_dump_close(lcookie->dumper);
    pcap_close(lcookie->libp);

    free(cookie);
  }
  return result;
}

usage_result_t usage() {
  usage_result_t result;

  // clang-format off
  result.params = "[-mode <overwrite, append>]\n"
  "[-default-ip <IP>]\n"
  "[-default-transport <dgram, stream>] <FILE_PATH>";
  result.usage = 
  "Write the contents of the packet to FILE_PATH in PCAP format.\n"
  "Optionally specify a mode to determine how existing contents\n"
  "of FILE_PATH are handled. Optionally specify a default-ip to\n"
  "specify a target IP if the packet does not have one. Optionally\n"
  "specify a default-transport protocol if the packet does not have\n"
  "one.";
  // clang-format on

  return result;
}

bool load(plugin_t *info) {
  info->name = plugin_name;
  info->configurator = generate_configuration;
  info->generator = generate;
  info->cleanup = cleanup;
  info->usage = usage;
  return true;
}