#ifndef __PLINEY_TYPES_HPP
#define __PLINEY_TYPES_HPP

#if __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

typedef struct {
  size_t len;
  uint8_t *data;
} data_p;

#if __cplusplus
}
#endif

#endif