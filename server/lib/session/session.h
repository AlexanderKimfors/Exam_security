#ifndef SESSION_H
#define SESSION_H

#include <stdbool.h>
#include <stdint.h>

typedef enum
{
    SESSION_REQ_CLOSE = 0,
    SESSION_REQ_GET_TEMP,
    SESSION_REQ_TOGGLE_LED
} session_request_t;

void session_init(void);

/* Returns true when session is active */
bool session_is_active(void);

/* Blocks until session is established or fails */
bool session_establish(void);

/* Read and decrypt a request */
session_request_t session_get_request(void);

/* Encrypted responses */
bool session_send_temperature(float temp);
void session_close(void);

#endif