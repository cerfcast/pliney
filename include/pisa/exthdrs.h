#ifndef _API_EXTHDRS_H
#define _API_EXTHDRS_H

#include "pisa/pisa.h"
#ifdef __cplusplus
extern "C" {
#endif

bool add_ip_opt_ext(pisa_ip_opts_exts_t *extensions, pisa_ip_opt_ext_t opt_ext_to_add);
bool remove_ip_opt_ext(pisa_ip_opts_exts_t *extensions, size_t index);

bool find_first_ip_ext(pisa_ip_opts_exts_t extensions, size_t *index, uint8_t type);
bool find_next_ip_ext(pisa_ip_opts_exts_t extensions, size_t *start_found, uint8_t type);
bool coalesce_ip_opts_exts(pisa_ip_opts_exts_t *extensions, uint8_t type);
bool to_raw_ip_opts_exts(pisa_ip_opt_ext_t extension, size_t *len,
                         uint8_t **raw);
pisa_ip_opts_exts_t copy_ip_opts_exts(pisa_ip_opts_exts_t extensions);
void free_ip_opts_exts(pisa_ip_opts_exts_t extensions);
pisa_ip_opt_ext_t *copy_ipextension(pisa_ip_opt_ext_t *extension);

#ifdef __cplusplus
}
#endif


#endif
