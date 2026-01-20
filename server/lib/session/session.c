#include <string.h>
#include "session.h"
#include <sys/time.h>
#include "communication.h"
#include <stdio.h> // For sscanf

#include <esp_random.h>
#include <bootloader_random.h>

#include <psa/crypto.h>

#include "driver/gpio.h" // Debug

/* Size in bytes */
#define AES_KEY_SIZE 32
#define SESSION_ID_SIZE 8
#define IV_SIZE 12
#define TAG_SIZE 16
#define RAND_SIZE 8
#define TIME_STAMP_SIZE 8
#define REQUEST_SIZE 1
#define MAX_PAYLOAD_SIZE_TX (sizeof(float) + TIME_STAMP_SIZE)
#define MAX_PAYLOAD_SIZE_RX (AES_KEY_SIZE + RAND_SIZE)
#define STATUS_SIZE 1

/* Size in bits */
#define BYTE_SIZE 8

#define UART_WAIT_TICKS 200

#define SESSION_TIMEOUT_US (60ULL * 1000000ULL)

typedef struct
{
    bool active;
    uint8_t id[SESSION_ID_SIZE];
    uint64_t latest_msg; // timestamp from the latest msg
} session_ctx_t;

typedef enum
{
    SESSION_EXPIRED = -1,
    SESSION_ERROR = 0,
    SESSION_OK = 1
} session_status_t;

typedef union
{
    float f;
    uint8_t b[sizeof(float)];
} float_bytes_t;

static session_ctx_t session;
static session_status_t session_status;
static psa_key_handle_t gcm_key = 0;
static uint8_t iv[IV_SIZE];
static uint8_t tx_buf[IV_SIZE + MAX_PAYLOAD_SIZE_TX + TAG_SIZE];
static uint8_t rx_buf[IV_SIZE + MAX_PAYLOAD_SIZE_RX + TAG_SIZE];

static bool gcm_init_psa(const uint8_t *key);
static void set_rtc_from_timestamp(uint64_t timestamp_us);
static bool handle_handshake_1(uint8_t *key, uint8_t *session_id);
static bool handle_handshake_2(uint8_t *key, uint8_t *session_id);
static void hex_to_bytes(const char *hex, uint8_t *out, size_t len);
static inline void write_be64(uint8_t *buf, uint64_t v);
static bool encrypt(uint8_t *plaintext, uint8_t *cipher, size_t msg_len, uint8_t *AAD, size_t AAD_len);
static bool decrypt(uint8_t *cipher, uint8_t *plaintext, size_t cipher_len, uint8_t *AAD, size_t AAD_len);
static bool send(uint8_t *cipher, size_t len);
static bool read(uint8_t *cipher, size_t len);
static bool read_timeout(uint8_t *cipher, size_t len_cipher, size_t wait_ml);

bool session_init()
{
    bool status = false;
    session.active = false;
    memset(session.id, 0, SESSION_ID_SIZE);

    if (communication_init(SPEED))
    {
        if (psa_crypto_init() == PSA_SUCCESS)
        {
            status = true;
        }
    }

    return status;
}

bool session_close(void)
{
    bool status = false;

    uint8_t plaintext[STATUS_SIZE + TIME_STAMP_SIZE];
    uint8_t cipher[STATUS_SIZE + TIME_STAMP_SIZE + TAG_SIZE];

    size_t offset = 0;
    plaintext[offset] = session_status;
    offset += STATUS_SIZE;
    uint8_t timestamp_b[TIME_STAMP_SIZE];
    write_be64(timestamp_b, session.latest_msg);
    memcpy(plaintext + offset, timestamp_b, TIME_STAMP_SIZE);

    if (encrypt(plaintext, cipher, sizeof(plaintext), session.id, SESSION_ID_SIZE))
    {
        if (send(cipher, sizeof(cipher)))
        {
            status = true;
        }
    }

    session.active = false;
    memset(session.id, 0, SESSION_ID_SIZE);
    memset(&session.latest_msg, 0, TIME_STAMP_SIZE);
    memset(iv, 0, IV_SIZE);

    psa_destroy_key(gcm_key);
    gcm_key = 0;

    return status;
}

bool session_is_active(void)
{
    return session.active;
}

session_request_t session_get_request(void)
{
    session_request_t req = INVALID;
    /* ===================== Extract the msg and decrypt it  ========================= */
    uint8_t plaintext[REQUEST_SIZE + TIME_STAMP_SIZE] = {0};
    uint8_t cipher[REQUEST_SIZE + TIME_STAMP_SIZE + TAG_SIZE] = {0};

    if (read(cipher, sizeof(cipher)))
    {
        if (decrypt(cipher, plaintext, sizeof(cipher), session.id, SESSION_ID_SIZE))
        {
            /* =================== Extract the request and time from msg ====================== */

            req = (session_request_t)plaintext[0];

            /* Convert timestamp (big-endian) to uint64 */
            uint64_t time_stamp = 0;
            for (int i = 0; i < TIME_STAMP_SIZE; i++)
            {
                time_stamp = (time_stamp << BYTE_SIZE) |
                             plaintext[REQUEST_SIZE + i];
            }
            /* ================================================================================ */

            /* ============================== Validate request ================================ */
            if (time_stamp < session.latest_msg) /* Not valid msg */
            {
                req = INVALID;
            }
            else if ((time_stamp - session.latest_msg) > SESSION_TIMEOUT_US) /* Session SESSION_EXPIRED, close the session */
            {
                session.latest_msg = time_stamp;
                session_status = SESSION_EXPIRED;
                session_close();
                req = INVALID;
            }
            else if (req == CLOSE_SESSION)
            {
                session.latest_msg = time_stamp;
                session_status = SESSION_OK;
                session_close();
            }
            else
            {
                session.latest_msg = time_stamp;
            }
            /* ================================================================================ */
        }
        else
        {
            req = INVALID;
        }
    }
    else
    {
        req = INVALID;
    }

    return req;
}

bool session_establish(void)
{
    bool status = false;
    uint8_t psa_key[AES_KEY_SIZE];
    uint8_t session_id[SESSION_ID_SIZE] = {0};

    hex_to_bytes(HSECRET, psa_key, AES_KEY_SIZE);

    if (gcm_init_psa(psa_key))
    {
        if (handle_handshake_1(psa_key, session_id))
        {
            if (handle_handshake_2(psa_key, session_id))
            {
                status = true;
                session_status = SESSION_OK;
            }
        }
    }

    return status;
}

static bool handle_handshake_1(uint8_t *key, uint8_t *session_id)
{
    bool status = false;
    uint8_t plaintext[AES_KEY_SIZE + SESSION_ID_SIZE];
    uint8_t cipher_received[AES_KEY_SIZE + SESSION_ID_SIZE + TAG_SIZE];
    uint8_t cipher_send[SESSION_ID_SIZE + TAG_SIZE];
    uint8_t rand[RAND_SIZE];

    if (read(cipher_received, sizeof(cipher_received)))
    {
        if (decrypt(cipher_received, plaintext, sizeof(cipher_received), session_id, SESSION_ID_SIZE))
        {
            memcpy(key, plaintext, AES_KEY_SIZE);
            memcpy(rand, plaintext + AES_KEY_SIZE, RAND_SIZE);

            if (gcm_init_psa(key))
            {
                if (psa_generate_random(session_id, SESSION_ID_SIZE) == PSA_SUCCESS)
                {
                    if (encrypt(session_id, cipher_send, SESSION_ID_SIZE, rand, RAND_SIZE))
                    {
                        status = send(cipher_send, sizeof(cipher_send));
                    }
                }
            }
        }
    }

    return status;
}

static bool handle_handshake_2(uint8_t *key, uint8_t *session_id)
{
    bool status = false;
    uint8_t plaintext[TIME_STAMP_SIZE];
    uint8_t cipher[TIME_STAMP_SIZE + TAG_SIZE];

    if (read_timeout(cipher, sizeof(cipher), UART_WAIT_TICKS))
    {
        if (decrypt(cipher, plaintext, sizeof(cipher), session_id, SESSION_ID_SIZE))
        {
            /* Convert timestamp (big-endian) to uint64 */
            uint64_t timestamp_us = 0;
            for (int i = 0; i < BYTE_SIZE; i++)
            {
                timestamp_us = (timestamp_us << BYTE_SIZE) | plaintext[i];
            }

            set_rtc_from_timestamp(timestamp_us);

            if (encrypt(plaintext, cipher, sizeof(plaintext), session_id, SESSION_ID_SIZE))
            {
                if (send(cipher, sizeof(cipher)))
                {
                    /* Establish session */
                    session.active = true;
                    session.latest_msg = timestamp_us;
                    memcpy(session.id, session_id, SESSION_ID_SIZE);
                    status = true;
                }
            }
        }
    }

    return status;
}

bool session_send_temperature(bool temp_status, float temp)
{
    bool status = false;
    float_bytes_t fb;
    fb.f = temp;

    uint8_t cipher[sizeof(bool) + TIME_STAMP_SIZE + sizeof(float) + TAG_SIZE];
    uint8_t plaintext[sizeof(bool) + TIME_STAMP_SIZE + sizeof(float)];

    uint8_t timestamp_b[TIME_STAMP_SIZE];
    write_be64(timestamp_b, session.latest_msg);

    size_t offset = 0;
    plaintext[offset] = (int8_t)(temp_status ? SESSION_OK : SESSION_ERROR);
    offset += sizeof(temp_status);
    memcpy(plaintext + offset, timestamp_b, TIME_STAMP_SIZE);
    offset += TIME_STAMP_SIZE;
    memcpy(plaintext + offset, &fb.f, sizeof(float));

    if (encrypt(plaintext, cipher, sizeof(plaintext), session.id, SESSION_ID_SIZE))
    {
        status = send(cipher, sizeof(cipher));
    }

    return status;
}

bool session_send_toggle_led(bool status, int state)
{
    uint8_t cipher[sizeof(bool) + TIME_STAMP_SIZE + sizeof(bool) + TAG_SIZE];
    uint8_t plaintext[sizeof(bool) + TIME_STAMP_SIZE + sizeof(bool)];

    uint8_t timestamp_b[TIME_STAMP_SIZE];
    write_be64(timestamp_b, session.latest_msg);

    plaintext[0] = (int8_t)(status ? SESSION_OK : SESSION_ERROR);
    memcpy(plaintext + sizeof(bool), timestamp_b, TIME_STAMP_SIZE);
    plaintext[sizeof(bool) + TIME_STAMP_SIZE] = state;

    if (encrypt(plaintext, cipher, sizeof(plaintext), session.id, SESSION_ID_SIZE))
    {
        status = send(cipher, sizeof(cipher));
    }

    return status;
}

static void set_rtc_from_timestamp(uint64_t timestamp_us)
{
    struct timeval tv;

    tv.tv_sec = timestamp_us / 1000000ULL;
    tv.tv_usec = timestamp_us % 1000000ULL;

    settimeofday(&tv, NULL);
}

static void hex_to_bytes(const char *hex, uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        sscanf(hex + 2 * i, "%2hhx", &out[i]);
    }
}

static inline void write_be64(uint8_t *buf, uint64_t v)
{
    buf[0] = (v >> 56) & 0xFF;
    buf[1] = (v >> 48) & 0xFF;
    buf[2] = (v >> 40) & 0xFF;
    buf[3] = (v >> 32) & 0xFF;
    buf[4] = (v >> 24) & 0xFF;
    buf[5] = (v >> 16) & 0xFF;
    buf[6] = (v >> 8) & 0xFF;
    buf[7] = v & 0xFF;
}

static bool encrypt(uint8_t *plaintext, uint8_t *cipher, size_t msg_len, uint8_t *AAD, size_t AAD_len)
{
    bool status = false;
    size_t out_len;

    if (psa_generate_random(iv, IV_SIZE) == PSA_SUCCESS)
    {
        psa_status_t psa_status = psa_aead_encrypt(
            gcm_key,
            PSA_ALG_GCM,
            iv,
            IV_SIZE,
            AAD,
            AAD_len,
            plaintext,
            msg_len,
            cipher,
            msg_len + TAG_SIZE,
            &out_len);

        if (psa_status == PSA_SUCCESS)
        {
            status = true;
        }
    }

    return status;
}

static bool decrypt(uint8_t *cipher, uint8_t *plaintext, size_t cipher_len, uint8_t *AAD, size_t AAD_len)
{
    size_t out_len;
    size_t plaintext_len = cipher_len - TAG_SIZE;

    psa_status_t status = psa_aead_decrypt(
        gcm_key,
        PSA_ALG_GCM,
        iv,
        IV_SIZE,
        AAD,
        AAD_len,
        cipher,
        cipher_len,
        plaintext,
        plaintext_len,
        &out_len);

    return status == PSA_SUCCESS;
}

static bool send(uint8_t *cipher, size_t len)
{
    memcpy(tx_buf, iv, IV_SIZE);
    memcpy(tx_buf + IV_SIZE, cipher, len);

    return (communication_write(tx_buf, IV_SIZE + len));
}

static bool read(uint8_t *cipher, size_t len_cipher)
{
    bool status = false;

    int len = communication_read(rx_buf, IV_SIZE + len_cipher);

    if (len == (IV_SIZE + len_cipher))
    {
        memcpy(iv, rx_buf, IV_SIZE);
        memcpy(cipher, rx_buf + IV_SIZE, len_cipher);

        status = true;
    }

    return status;
}

static bool read_timeout(uint8_t *cipher, size_t len_cipher, size_t wait_ml)
{
    bool status = false;

    int len = communication_read_timeout(rx_buf, IV_SIZE + len_cipher, wait_ml);

    if (len == IV_SIZE + len_cipher)
    {
        memcpy(iv, rx_buf, IV_SIZE);
        memcpy(cipher, rx_buf + IV_SIZE, len_cipher);

        status = true;
    }

    return status;
}

static bool gcm_init_psa(const uint8_t *key)
{
    if (gcm_key != 0)
    {
        psa_destroy_key(gcm_key);
        gcm_key = 0;
    }

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, AES_KEY_SIZE * 8);
    psa_set_key_usage_flags(&attr,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);

    return (PSA_SUCCESS == psa_import_key(&attr, key, AES_KEY_SIZE, &gcm_key));
}