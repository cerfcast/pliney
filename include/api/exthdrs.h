#ifndef _API_EXTHDRS_H
#define _API_EXTHDRS_H

#include "api/plugin.h"


#ifdef __cplusplus
extern "C" {
#endif

bool add_extension(extensions_p *extensions, size_t *index);
bool remove_extension(extensions_p *extensions, size_t index);

bool find_first_extension(extensions_p extensions, size_t *index, uint8_t type);
bool find_next_extension(extensions_p extensions, size_t *start_found, uint8_t type);
bool coalesce_extensions(extensions_p *extensions, uint8_t type);
extensions_p copy_extensions(extensions_p extensions);
void free_extensions(extensions_p extensions);
extension_p *copy_extension(extension_p *extension);

#ifdef __cplusplus
}
#endif


#endif
