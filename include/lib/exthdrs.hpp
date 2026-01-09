#ifndef __EXTHDRS_HPP
#define __EXTHDRS_HPP

#include <cstddef>
#include <cstdint>

#include "pisa/exthdr.h"

bool add_ip_opt_ext(pisa_ip_opts_exts_t *extensions, pisa_ip_opt_ext_t opt_ext_to_add);
bool remove_ip_opt_ext(pisa_ip_opts_exts_t *extensions, size_t index);

bool find_first_ip_ext(pisa_ip_opts_exts_t extensions, size_t *index, uint8_t type);
bool find_next_ip_ext(pisa_ip_opts_exts_t extensions, size_t *start_found, uint8_t type);
pisa_ip_opt_ext_t coalesce_ip_opts_exts(pisa_ip_opts_exts_t extensions, pisa_ip_opt_or_ext_type_t type);
bool to_raw_ip_opts_exts(pisa_ip_opt_ext_t extension, size_t *len,
                         uint8_t **raw);

bool from_raw_ip_opts_exts(uint8_t *data, uint8_t this_header_raw,
                           pisa_ip_opt_ext_t *extension,
                           uint8_t *next_header_raw);

pisa_ip_opts_exts_t copy_ip_opts_exts(pisa_ip_opts_exts_t extensions);

void free_ip_opt_ext(pisa_ip_opt_ext_t opt_ext);
void free_ip_opts_exts(pisa_ip_opts_exts_t extensions);
pisa_ip_opt_ext_t *copy_ipextension(pisa_ip_opt_ext_t *extension);

pisa_ip_opt_or_ext_type_t *supported_exts_ip_opts_exts(size_t *count);

uint8_t to_native_ext_type_ip_opts_exts(pisa_ip_opt_or_ext_type_t op_ext_type);
pisa_ip_opt_or_ext_type_t from_native_ext_type_ip_opts_exts(uint8_t op_ext_type);
uint8_t to_sockopt_ext_type_ip_opts_exts(pisa_ip_opt_or_ext_type_t op_ext_type);

#endif
