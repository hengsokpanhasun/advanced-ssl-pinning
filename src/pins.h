/* Compiled-in obfuscated pin set (see pins.c). */
#ifndef ASPIN_PINS_H
#define ASPIN_PINS_H

#include <stdint.h>
#include "aspin.h"

#define ASPIN_PIN_COUNT 2
#define ASPIN_SECRET_LEN 13 /* "aspin/mask/v1", "aspin/root/v1" */

extern const uint8_t ASPIN_MASK_SECRET[ASPIN_SECRET_LEN];
extern const uint8_t ASPIN_ROOT_SECRET[ASPIN_SECRET_LEN];
extern const uint8_t ASPIN_MASKED_PINS[ASPIN_PIN_COUNT][ASPIN_PIN_LEN];

#endif
