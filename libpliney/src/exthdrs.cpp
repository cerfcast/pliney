#include "lib/safety.hpp"
#include "pisa/exthdr.h"
#include "pisa/pisa.h"
#include "pisa/utils.h"
#include <netinet/in.h>
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

  debug("Added an IP opt/ext; there are now %lu options/extensions",
        extensions->opts_exts_count);

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

void free_ip_opt_ext(pisa_ip_opt_ext_t opt_ext) { free(opt_ext.data); }

void free_ip_opts_exts(pisa_ip_opts_exts_t extensions) {
  for (size_t i = 0; i < extensions.opts_exts_count; i++) {
    free_ip_opt_ext(extensions.opt_ext_values[i]);
  }
  free(extensions.opt_ext_values);
}

pisa_ip_opt_ext_t coalesce_ip_opts_exts(pisa_ip_opts_exts_t extensions,
                                        pisa_ip_opt_or_ext_type_t op_ext) {
  pisa_ip_opt_ext_t coalesced_ip_opt = {.oe = op_ext, .len = 0, .data = NULL};
  size_t next_index = 0;

  while (find_next_ip_ext(extensions, &next_index, op_ext)) {
    debug("Found (one) to coalesce at %d!", next_index);

    // First, update the coalesced size.
    uint8_t new_size =
        coalesced_ip_opt.len + extensions.opt_ext_values[next_index].len;

    // Second, add some new data!
    coalesced_ip_opt.data =
        (uint8_t *)realloc(coalesced_ip_opt.data, sizeof(uint8_t) * new_size);
    memcpy(coalesced_ip_opt.data + coalesced_ip_opt.len,
           extensions.opt_ext_values[next_index].data,
           extensions.opt_ext_values[next_index].len);
    coalesced_ip_opt.len = new_size;
    next_index += 1;
  }

  debug("Done coalescing IP extensions.");
  return coalesced_ip_opt;
}

uint8_t to_native_ext_type_ip_opts_exts(pisa_ip_opt_or_ext_type_t op_ext_type) {
  switch (op_ext_type.ext_type) {
    case IPV6_DSTOPTS: {
      return IPPROTO_DSTOPTS;
    }
    case IPV6_HOPOPTS: {
      return IPPROTO_HOPOPTS;
    }
  }
  PLINEY_UNREACHABLE;
}

uint8_t to_sockopt_ext_type_ip_opts_exts(pisa_ip_opt_or_ext_type_t op_ext_type) {
  return op_ext_type.ext_type;
}

pisa_ip_opt_or_ext_type_t
from_native_ext_type_ip_opts_exts(uint8_t op_ext_type) {
  pisa_ip_opt_or_ext_type_t res;
  switch (op_ext_type) {
    case IPPROTO_DSTOPTS: {
      res.ext_type = IPV6_DSTOPTS;
      return res;
    }
    case IPPROTO_HOPOPTS: {
      res.ext_type = IPV6_HOPOPTS;
      return res;
    }
  }
  PLINEY_UNREACHABLE;
}

bool to_raw_ip_opts_exts(pisa_ip_opt_ext_t extension, size_t *len,
                         uint8_t **raw) {
  *len = ((2 /* for extension header T/L */ + extension.len + (8 - 1)) / 8) * 8;

  *raw = (uint8_t *)calloc(*len, sizeof(uint8_t));

  (*raw)[0] = 0; // Next header.
  (*raw)[1] = (*len / 8) - 1;
  memcpy(*raw + 2, extension.data, extension.len);

  return true;
}

bool from_raw_ip_opts_exts(uint8_t *data, uint8_t this_header_raw,
                           pisa_ip_opt_ext_t *extension,
                           uint8_t *next_header_raw) {
  // There is an extension header.
  size_t parsing_offset = 0;

  *next_header_raw = *(uint8_t *)WITH_OFFSET(data, 0);

  parsing_offset += sizeof(uint8_t);
  uint32_t ext_length =
      (((*(uint8_t *)WITH_OFFSET(data, parsing_offset)) + 1) * 8) -
      2 /* For T/L */;
  parsing_offset += sizeof(uint8_t);
  uint8_t *ext_data = WITH_OFFSET(data, parsing_offset);

  extension->oe = from_native_ext_type_ip_opts_exts(this_header_raw);
  extension->len = ext_length;
  extension->data = ext_data;

  return true;
}

static pisa_ip_opt_or_ext_type_t SUPPORTED_EXTS[] = {{.ext_type = IPV6_HOPOPTS}, {.ext_type = IPV6_DSTOPTS}};
static uint8_t SUPPORTED_EXTS_COUNT = 2;

pisa_ip_opt_or_ext_type_t *supported_exts_ip_opts_exts(size_t *count) {
  *count = SUPPORTED_EXTS_COUNT;
  return SUPPORTED_EXTS;
}
