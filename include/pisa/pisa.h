#ifndef __PISA_PISA_H
#define __PISA_PISA_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

#include "lib/types.hpp"
#include "exthdr.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  uint8_t diffserv;
  uint8_t cong;
  uint8_t ttl;
} header_p;

#define PLINEY_IPVERSION4 44
#define PLINEY_IPVERSION6 66

#define PLINEY_TCP 6
#define PLINEY_UDP 17
#define PLINEY_ICMP 1
#define PLINEY_ICMP6 58

typedef struct {
  uint8_t family;
  union {
    struct in_addr ipv4;
    struct in6_addr ipv6;
  } addr;
  uint16_t port;
} ip_addr_t;

typedef struct {
  data_p all;
  data_p ip;
  data_p ip_opts_exts;
  data_p transport;
  data_p transport_options;
  data_p body;
} packet_t;


typedef enum {
  SET_META,
  SET_FIELD,
  SET_IP_OPT_EXT,
  ADD_IP_OPT_EXT,
  SET_TRANSPORT_EXTENSION,
  ADD_TRANSPORT_EXTENSION,
  SET_OFFSET,
  ADD_OBSERVER,
  EXEC_AFTER_SOCKET_BUILT,
  EXEC_AFTER_PACKET_BUILT,
  PISA_OPCODE_MAX,
} pisa_opcode_t;

typedef enum {
  ETHERNET,
  IPV4,
  IPV6,
  UDP,
  TCP,
} pisa_protocol_t;

typedef size_t pisa_offset_t;

typedef enum {
  IPV4_TTL,
  IPV6_HL, // Spelled funny to avoid interdependence with OS constant.
  IPV4_TARGET,
  IPV6_TARGET,
  IPV4_SOURCE,
  IPV6_SOURCE,
  IPV4_SOURCE_PORT,
  IPV4_TARGET_PORT,
  IPV6_SOURCE_PORT,
  IPV6_TARGET_PORT,
  IP_ECN,
  IP_DSCP,
  ICMP_TYPE,
  ICMP_CODE,
  ICMP_DEPENDS,
  APPLICATION_BODY,
  PISA_FIELD_MAX,
} pisa_field_t;

typedef enum {
  UNKNOWN = 0,
  BYTE,
  FOUR_BYTES,
  EIGHT_BYTES,
  SIZE_T,
  PTR,
  CALLBACK,
  IP_OPT,
  IP_EXT,
} pisa_value_type_t;

typedef struct {
  uint8_t *data;
  size_t len;
} pisa_ptr_value_t;

typedef struct {
  void *callback;
  void *cookie;
} pisa_callback_t;

typedef struct {
  pisa_value_type_t tpe;
  union {
    uint8_t byte;
    uint32_t four_bytes;
    uint64_t eight_bytes;
    ip_addr_t ipaddr;
    size_t szt;
    pisa_ptr_value_t ptr;
    pisa_callback_t callback;
    pisa_ip_opt_ext_t opt;
    pisa_ip_opt_ext_t ext;
  } value;
} pisa_value_t;

typedef struct {
  pisa_opcode_t op;
  pisa_protocol_t prot;
  pisa_offset_t offset;
  union {
    pisa_field_t field;
    pisa_ptr_value_t key;
  } fk;
  pisa_value_t value;
} pisa_inst_t;

typedef struct {
  size_t inst_count;
  pisa_inst_t *insts;
} pisa_program_t;

typedef void (*exec_packet_builder_cb)(packet_t packet, void *cookie);

pisa_program_t *pisa_program_new();
void pisa_program_release(pisa_program_t *program);

bool pisa_program_add_inst(pisa_program_t *pgm, pisa_inst_t *inst);
bool pisa_program_add_meta_inst(pisa_program_t *pgm, const char *key,
                                pisa_value_t value);
bool pisa_program_rem_inst(pisa_program_t *pgm, size_t pc);
bool pisa_program_find_inst(pisa_program_t *pgm, size_t *start, pisa_inst_t **inst, pisa_opcode_t op);
bool pisa_program_find_field_value(pisa_program_t *pgm, pisa_field_t field,
                                   pisa_value_t *value);
bool pisa_program_find_meta_value(pisa_program_t *pgm, const char *key,
                                  pisa_value_t *value);

bool pisa_program_find_target_value(pisa_program_t *pgm, pisa_value_t *value);
bool pisa_program_find_target_port_value(pisa_program_t *pgm, pisa_value_t *value);
bool pisa_program_find_target_family(pisa_program_t *pgm, uint8_t *family);

const char *pisa_field_name(pisa_field_t field);
const char *pisa_opcode_name(pisa_opcode_t opcode);

#ifdef __cplusplus
}
#endif

#endif