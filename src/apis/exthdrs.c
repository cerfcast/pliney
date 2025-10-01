#include "api/plugin.h"
#include "api/utils.h"
#include <stdlib.h>
#include <string.h>

bool add_extension(extensions_p *extensions, size_t *index) {
  size_t current_size = extensions->extensions_count;
  extension_p **new_extension_list =
      (extension_p **)realloc(extensions->extensions_values,
                              (current_size + 1) * sizeof(extension_p *));

  if (new_extension_list == NULL) {
    return false;
  }

  extensions->extensions_values = new_extension_list;
  *index = extensions->extensions_count;
  extensions->extensions_count++;

  debug("There are now %lu extensions\n", extensions->extensions_count);

  return true;
}

bool remove_extension(extensions_p *extensions, size_t index) {
  if (extensions->extensions_count == 0) {
    // Nothing to do.
    return true;
  }

  if (extensions->extensions_count == 1) {
    // Special case. TODO: Does it need to be?
    extensions->extensions_count = 0;
    free(extensions->extensions_values[0]->data);
    free(extensions->extensions_values[0]);
    free(extensions->extensions_values);
    extensions->extensions_values = NULL;
  } else {
    // Get the one to remove ...
    extension_p *to_remove = extensions->extensions_values[index];
    free(to_remove->data);
    free(to_remove);

    // Move the last extension into the removed slot.
    extensions->extensions_values[index] =
        extensions->extensions_values[extensions->extensions_count - 1];

    extension_p **new_extension_list = (extension_p **)realloc(
        extensions->extensions_values,
        (extensions->extensions_count - 1) * sizeof(extension_p *));

    if (new_extension_list == NULL) {
      return false;
    }

    extensions->extensions_count--;
    extensions->extensions_values = new_extension_list;
  }

  return true;
}

bool find_first_extension(extensions_p extensions, size_t *index,
                          uint8_t type) {
  debug("There are %d extensions \n", extensions.extensions_count);
  for (size_t i = 0; i < extensions.extensions_count; i++) {
    if (extensions.extensions_values[i]->type == type) {
      debug("Found the extension at %d\n", i);
      *index = i;
      return true;
    }
  }
  return false;
}

bool find_next_extension(extensions_p extensions, size_t *start_found,
                         uint8_t type) {

  if (*start_found >= extensions.extensions_count) {
    return false;
  }
  for (size_t i = *start_found; i < extensions.extensions_count; i++) {
    if (extensions.extensions_values[i]->type == type) {
      *start_found = i;
      return true;
    }
  }
  return false;
}

extension_p *copy_extension(extension_p *extension) {
  extension_p *result = (extension_p *)malloc(sizeof(extension_p));
  result->len = extension->len;
  result->type = extension->type;
  result->data = (uint8_t *)malloc(sizeof(uint8_t) * result->len);
  memcpy(result->data, extension->data, result->len);

  return result;
}

extensions_p copy_extensions(extensions_p extensions) {
  extensions_p result;

  result.extensions_count = extensions.extensions_count;
  result.extensions_values = (extension_p **)calloc(
      sizeof(extension_p *), extensions.extensions_count);
  for (size_t i = 0; i < result.extensions_count; i++) {
    result.extensions_values[i] = (extension_p *)malloc(sizeof(extension_p));
    result.extensions_values[i]->len = extensions.extensions_values[i]->len;
    result.extensions_values[i]->type = extensions.extensions_values[i]->type;
    result.extensions_values[i]->data = (uint8_t *)calloc(
        sizeof(uint8_t), extensions.extensions_values[i]->len);
    memcpy(result.extensions_values[i]->data,
           extensions.extensions_values[i]->data,
           extensions.extensions_values[i]->len);
  }

  return result;
}

void free_extensions(extensions_p extensions) {
  for (size_t i = 0; i < extensions.extensions_count; i++) {
    free(extensions.extensions_values[i]->data);
    free(extensions.extensions_values[i]);
  }
  free(extensions.extensions_values);
}

bool coalesce_extensions(extensions_p *extensions, uint8_t type) {
  size_t first_index = 0;
  if (!find_first_extension(*extensions, &first_index, type)) {
    return true;
  }

  debug("Found first at %d!\n", first_index);

  size_t next_index = first_index + 1;

  while (find_next_extension(*extensions, &next_index, type)) {
    debug("Found another to coalesce at %d!\n", next_index);

    uint8_t new_size = extensions->extensions_values[first_index]->len +
                       extensions->extensions_values[next_index]->len;
    uint8_t *new_data = (uint8_t *)calloc(new_size, sizeof(uint8_t));
    memcpy(new_data, extensions->extensions_values[first_index]->data,
           extensions->extensions_values[first_index]->len);
    memcpy(new_data + extensions->extensions_values[first_index]->len,
           extensions->extensions_values[next_index]->data,
           extensions->extensions_values[next_index]->len);

    free(extensions->extensions_values[first_index]->data);
    extensions->extensions_values[first_index]->data = new_data;
    extensions->extensions_values[first_index]->len = new_size;

    remove_extension(extensions, next_index);
  }

  return true;
}
