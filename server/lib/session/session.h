#ifndef SESSION_H
#define SESSION_H

#include <stdbool.h>
#include <stdint.h>

typedef enum
{
    INVALID = -1,
    CLOSE_SESSION = 0,
    GET_TEMP,
    TOGGLE_LED,
} session_request_t;

/**
 * @brief Initialize session
 *
 * @return true If successfully initialized the session
 * @return false If failed to initialize the session
 */
bool session_init(void);

/* Returns true when session is active */
bool session_is_active(void);

/* Blocks until session is established or fails */
bool session_establish(void);

/* Read and decrypt a request */
session_request_t session_get_request(void);

/* Encrypted responses */
bool session_send_temperature(bool status, float temp);

bool session_send_toggle_led(bool status, int state);

bool session_close(void);

#endif