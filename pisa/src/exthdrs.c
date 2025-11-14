#include "pisa/pisa.h"
#include "pisa/utils.h"
#include <stdlib.h>
#include <string.h>

#include <assert.h>

bool add_ip_opt_ext(pisa_ip_opts_exts_t *extensions,
                pisa_ip_opt_ext_t opt_ext_to_add) {
  size_t current_size = extensions->opts_exts_count;
  pisa_ip_opt_ext_t *existing_opts_exts = extensions->opt_ext_values;

  pisa_ip_opt_ext_t *new_extension_list = (pisa_ip_opt_ext_t *)realloc(
      extensions->opt_ext_values,
      (current_size + 1) * sizeof(pisa_ip_opt_ext_t));

  if (new_extension_list == NULL) {
    return false;
  }

  extensions->opt_ext_values = new_extension_list;
  extensions->opt_ext_values[current_size].data =
      (uint8_t *)calloc(opt_ext_to_add.len, sizeof(uint8_t));
  memcpy(extensions->opt_ext_values[current_size].data, opt_ext_to_add.data,
         opt_ext_to_add.len);
  extensions->opt_ext_values[current_size].len = opt_ext_to_add.len;
  extensions->opt_ext_values[current_size].oe = opt_ext_to_add.oe;

  extensions->opts_exts_count++;

  debug("Added an IP opt/ext; there are now %lu options/extensions", extensions->opts_exts_count);

  return true;
}

bool remove_ip_opt_ext(pisa_ip_opts_exts_t *extensions, size_t index) {

  if (index >= extensions->opts_exts_count) {
    return false;
  }

  // Zero, delete the existing data!
  free(extensions->opt_ext_values[index].data);

  // First, move the one at the last one into the place to remove!
  size_t last_index = extensions->opts_exts_count - 1;
  extensions->opt_ext_values[index] = extensions->opt_ext_values[last_index];

  // Second, make the list shorter by one!
  extensions->opt_ext_values = (pisa_ip_opt_ext_t *)realloc(
      extensions->opt_ext_values,
      sizeof(pisa_ip_opt_ext_t) * (extensions->opts_exts_count - 1));

  // Decrement the count!
  extensions->opts_exts_count--;
  return true;
}

bool find_next_ip_ext(pisa_ip_opts_exts_t extensions, size_t *start_found,
                      pisa_ip_opt_or_ext_type_t op_ext) {

  if (*start_found >= extensions.opts_exts_count) {
    return false;
  }
  for (size_t i = *start_found; i < extensions.opts_exts_count; i++) {
    if (extensions.opt_ext_values[i].oe.ext_type == op_ext.ext_type) {
      *start_found = i;
      return true;
    }
  }
  return false;
}

pisa_ip_opts_exts_t copy_ip_opts_exts(pisa_ip_opts_exts_t extensions) {
  pisa_ip_opts_exts_t result;

  result.opts_exts_count = extensions.opts_exts_count;
  result.opt_ext_values = (pisa_ip_opt_ext_t *)calloc(
      sizeof(pisa_ip_opt_ext_t), extensions.opts_exts_count);
  for (size_t i = 0; i < result.opts_exts_count; i++) {
    result.opt_ext_values[i] = extensions.opt_ext_values[i];

    result.opt_ext_values[i].data =
        (uint8_t *)calloc(extensions.opt_ext_values[i].len, sizeof(uint8_t));
    memcpy(result.opt_ext_values[i].data, extensions.opt_ext_values[i].data,
           extensions.opt_ext_values[i].len);
  }

  return result;
}

void free_ip_opts_exts(pisa_ip_opts_exts_t extensions) {
  for (size_t i = 0; i < extensions.opts_exts_count; i++) {
    free(extensions.opt_ext_values[i].data);
  }
  free(extensions.opt_ext_values);
}

bool coalesce_ip_opts_exts(pisa_ip_opts_exts_t *extensions, pisa_ip_opt_or_ext_type_t op_ext) {
  size_t first_index = 0;
  if (!find_next_ip_ext(*extensions, &first_index, op_ext)) {
    return true;
  }

  debug("Coalescing IP extensions with type %d", op_ext.ext_type);
  debug("Found first IP extension with type %d at %d!", op_ext.ext_type, first_index);

  size_t next_index = first_index + 1;

  while (find_next_ip_ext(*extensions, &next_index, op_ext)) {
    debug("Found another to coalesce at %d!", next_index);

    uint8_t new_size = extensions->opt_ext_values[first_index].len +
                       extensions->opt_ext_values[next_index].len;
    uint8_t *new_data = (uint8_t *)calloc(new_size, sizeof(uint8_t));
    memcpy(new_data, extensions->opt_ext_values[first_index].data,
           extensions->opt_ext_values[first_index].len);
    memcpy(new_data + extensions->opt_ext_values[first_index].len,
           extensions->opt_ext_values[next_index].data,
           extensions->opt_ext_values[next_index].len);

    free(extensions->opt_ext_values[first_index].data);
    extensions->opt_ext_values[first_index].data = new_data;
    extensions->opt_ext_values[first_index].len = new_size;

    remove_ip_opt_ext(extensions, next_index);
  }

  debug("Done coalescing IP extensions.");
  return true;
}
