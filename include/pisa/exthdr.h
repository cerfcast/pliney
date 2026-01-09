#ifndef __PISA_EXTHDRS_H
#define __PISA_EXTHDRS_H

#ifdef __cplusplus 
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

typedef union {
  uint8_t opt;
  uint8_t ext_type;
} pisa_ip_opt_or_ext_type_t;

typedef struct {
  pisa_ip_opt_or_ext_type_t oe;
  uint8_t len;
  uint8_t *data;
} pisa_ip_opt_ext_t;

typedef struct {
  size_t opts_exts_count;
  pisa_ip_opt_ext_t *opt_ext_values;
} pisa_ip_opts_exts_t;

#ifdef __cplusplus 
}
#endif

#endif