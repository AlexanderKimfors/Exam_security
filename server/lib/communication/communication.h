#ifndef COMMUNICAITON_H
#define COMMUNICATION_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

void uart_init(int speed);

bool uart_read_timeout(uint8_t *buf, size_t length, size_t wait_ticks);

bool uart_read(uint8_t *buf, size_t length);

bool uart_write(uint8_t *data, size_t length);

#endif