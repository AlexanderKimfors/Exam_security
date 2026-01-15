#ifndef COMMUNICAITON_H
#define COMMUNICATION_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Initialize the communication.
 *
 * @param params The necessary parameters to initialize the communication
 * @return true If it successfully initialized the communication
 * @return false If it failed to initialize the communication
 */
bool communication_init(const char *params);

/**
 * @brief Reads data from the UART port until the specified number of bytes
 *        has been received or timeout occurs. This is a blocking function.
 *
 * @param buf Pointer to the buffer where the received data will be stored.
 * @param length Number fo bytes to read.
 * @param wait_ms Maimum milli secunds to wait.
 * @return true If exactly @p length bytes were successfully read.
 * @return false If fewer then @p length bytes were read.
 */
int communication_read_timeout(uint8_t *buf, size_t length, size_t wait_ms);

/**
 * @brief Reads data from the UART port until the specified number of bytes
 *        has been received. This is a blocking function.
 *
 * @param buf Pointer to the buffer where the received data will be stored.
 * @param length Number fo bytes to read.
 * @return true If exactly @p length bytes were successfully read.
 * @return false If fewer then @p length bytes were read.
 */
int communication_read(uint8_t *buf, size_t length);

bool communication_write(uint8_t *data, size_t length);

#endif