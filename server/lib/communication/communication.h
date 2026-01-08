#ifndef COMMUNICAITON_H
#define COMMUNICATION_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

bool communication_init(const char *params);

bool communication_read_timeout(uint8_t *buf, size_t length, size_t wait_ticks);

bool communication_read(uint8_t *buf, size_t length);

bool communication_write(uint8_t *data, size_t length);

#endif