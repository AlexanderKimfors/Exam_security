#include <string.h>
#include "session.h"
#include <sys/time.h>
#include "communication.h"

#include <esp_random.h>
#include <bootloader_random.h>

#include <mbedtls/gcm.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

/* Size in bytes */
#define AES_KEY_SIZE 32
#define SESSION_ID_SIZE 8
#define IV_SIZE 12
#define TAG_SIZE 16
#define RAND_SIZE 8
#define TIME_STAMP_SIZE 8

/* Size in bits */
#define BYTE_SIZE 8
#define REQUEST_SIZE 1

#define UART_WAIT_TICKS 200

typedef struct
{
    bool active;
    uint8_t key[AES_KEY_SIZE];
    uint8_t id[SESSION_ID_SIZE];
} session_ctx_t;

static session_ctx_t session;
static uint8_t iv[IV_SIZE];
static uint8_t tag[TAG_SIZE];
static uint8_t tx_buf[IV_SIZE + SESSION_ID_SIZE + TAG_SIZE];
static uint8_t rx_buf[IV_SIZE + AES_KEY_SIZE + RAND_SIZE + TAG_SIZE];

static mbedtls_gcm_context gcm;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;

static void random_init(void);
static void gcm_init(const uint8_t *key);
static void set_rtc_from_timestamp(uint64_t timestamp_us);
static bool handle_handshake_1(uint8_t *key, uint8_t *session_id);
static bool handle_handshake_2(uint8_t *key, uint8_t *session_id);

void session_init()
{
    session.active = false;
    memset(session.key, 0, AES_KEY_SIZE);
    memset(session.id, 0, SESSION_ID_SIZE);
    random_init();
    uart_init(SPEED);
}

bool session_is_active(void)
{
    return session.active;
}

session_request_t session_get_request(void)
{
    uint8_t plain_request = 0;
    uint8_t cipher_request = 0;

    uart_read(rx_buf, IV_SIZE + REQUEST_SIZE + TAG_SIZE);

    size_t offset = 0;
    memcpy(iv, rx_buf + offset, IV_SIZE);
    offset += IV_SIZE;

    cipher_request = rx_buf[offset];
    offset += REQUEST_SIZE;

    memcpy(tag, rx_buf + offset, TAG_SIZE);

    gcm_init(session.key);

    int ret = mbedtls_gcm_auth_decrypt(
        &gcm,
        REQUEST_SIZE,
        iv,
        IV_SIZE,
        session.id,
        SESSION_ID_SIZE,
        tag,
        TAG_SIZE,
        &cipher_request,
        &plain_request);

    return (session_request_t)plain_request;
}

bool session_establish(void)
{
    bool status = false;
    uint8_t aes_key[AES_KEY_SIZE];
    uint8_t session_id[SESSION_ID_SIZE] = {0};
    int ret = 0;

    if (handle_handshake_1(aes_key, session_id))
    {
        if (handle_handshake_2(aes_key, session_id))
        {
            status = true;
        }
    }

    return status;
}

/* Not implemented */
bool session_send_temperature(float temp)
{
    return false;
}

void session_close(void)
{
    session.active = false;

    memset(session.key, 0, AES_KEY_SIZE);
    memset(session.id, 0, SESSION_ID_SIZE);

    mbedtls_gcm_free(&gcm);

    // Set LED to red
}

static bool handle_handshake_1(uint8_t *key, uint8_t *session_id)
{
    bool status = false;
    uint8_t plaintext[AES_KEY_SIZE + SESSION_ID_SIZE];
    uint8_t ciphertext[AES_KEY_SIZE + SESSION_ID_SIZE];
    uint8_t rand[RAND_SIZE];
    int ret = 0;

    if (uart_read(rx_buf, IV_SIZE + AES_KEY_SIZE + RAND_SIZE + TAG_SIZE))
    {
        /* Extract the individual components from the received message */
        size_t offset = 0;
        memcpy(iv, rx_buf + offset, IV_SIZE);
        offset += IV_SIZE;
        memcpy(ciphertext, rx_buf + offset, AES_KEY_SIZE + RAND_SIZE);
        offset += AES_KEY_SIZE + RAND_SIZE;
        memcpy(tag, rx_buf + offset, TAG_SIZE);

        /* Convert SECRET to uint8_t array */
        memcpy(key, SECRET, AES_KEY_SIZE);

        gcm_init(key);

        ret = mbedtls_gcm_auth_decrypt(
            &gcm,
            AES_KEY_SIZE + RAND_SIZE, // Size of the msg
            iv,
            IV_SIZE,
            session_id, // AAD
            SESSION_ID_SIZE,
            tag,
            TAG_SIZE,
            ciphertext,
            plaintext);

        if (ret == 0)
        {
            /* Extract the AES_KEY */
            memcpy(key, plaintext, AES_KEY_SIZE);

            /* Extract the RAND */
            memcpy(rand, plaintext + AES_KEY_SIZE, RAND_SIZE);

            gcm_init(key);

            if ((mbedtls_ctr_drbg_random(&ctr_drbg, session_id, SESSION_ID_SIZE) == 0) && (mbedtls_ctr_drbg_random(&ctr_drbg, iv, IV_SIZE) == 0))
            {

                ret = mbedtls_gcm_crypt_and_tag(
                    &gcm,
                    MBEDTLS_GCM_ENCRYPT,
                    SESSION_ID_SIZE, // Size of the msg
                    iv,
                    IV_SIZE,
                    rand, // AAD
                    RAND_SIZE,
                    session_id, // Plaintext msg to be encrypted
                    ciphertext,
                    TAG_SIZE,
                    tag);

                if (ret == 0)
                {
                    offset = 0;
                    memcpy(tx_buf, iv, IV_SIZE);
                    offset = IV_SIZE;
                    memcpy(tx_buf + offset, ciphertext, SESSION_ID_SIZE);
                    offset += SESSION_ID_SIZE;
                    memcpy(tx_buf + offset, tag, TAG_SIZE);

                    if (uart_write(tx_buf, IV_SIZE + SESSION_ID_SIZE + TAG_SIZE))
                    {
                        status = true;
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
    uint8_t ciphertext[TIME_STAMP_SIZE];

    if (uart_read_timeout(rx_buf, IV_SIZE + TIME_STAMP_SIZE + TAG_SIZE, UART_WAIT_TICKS))
    {
        /* Extract the individual components from the received message */
        int offset = 0;
        memcpy(iv, rx_buf, IV_SIZE);
        offset += IV_SIZE;
        memcpy(ciphertext, rx_buf + offset, TIME_STAMP_SIZE);
        offset += TIME_STAMP_SIZE;
        memcpy(tag, rx_buf + offset, TAG_SIZE);

        /* Mbed TLS requires the GCM context to be reinitialized every time */
        gcm_init(key);

        int ret = mbedtls_gcm_auth_decrypt(
            &gcm,
            TIME_STAMP_SIZE, // Size of the msg
            iv,
            IV_SIZE,
            session_id, // AAD
            SESSION_ID_SIZE,
            tag,
            TAG_SIZE,
            ciphertext,
            plaintext);

        if (ret == 0)
        {
            /* Convert timestamp (big-endian) to uint64 */
            uint64_t timestamp_us = 0;
            for (int i = 0; i < BYTE_SIZE; i++)
            {
                timestamp_us = (timestamp_us << BYTE_SIZE) | plaintext[i];
            }

            set_rtc_from_timestamp(timestamp_us);

            if (mbedtls_ctr_drbg_random(&ctr_drbg, iv, IV_SIZE) == 0)
            {
                /* Mbed TLS requires the GCM context to be reinitialized every time */
                gcm_init(key);

                ret = mbedtls_gcm_crypt_and_tag(
                    &gcm,
                    MBEDTLS_GCM_ENCRYPT,
                    TIME_STAMP_SIZE, // Size of the msg
                    iv,
                    IV_SIZE,
                    session_id, // AAD
                    SESSION_ID_SIZE,
                    plaintext, // received timestamp
                    ciphertext,
                    TAG_SIZE,
                    tag);

                if (ret == 0)
                {
                    offset = 0;
                    memcpy(tx_buf, iv, IV_SIZE);
                    offset += IV_SIZE;
                    memcpy(tx_buf + offset, ciphertext, TIME_STAMP_SIZE);
                    offset += TIME_STAMP_SIZE;
                    memcpy(tx_buf + offset, tag, TAG_SIZE);

                    if (uart_write(tx_buf, IV_SIZE + TIME_STAMP_SIZE + TAG_SIZE))
                    {
                        /* Establish session */
                        session.active = true;
                        memcpy(session.id, session_id, SESSION_ID_SIZE);
                        memcpy(session.key, key, AES_KEY_SIZE);

                        status = true;
                    }
                }
            }
        }
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

static void random_init(void)
{
    uint8_t buffer[AES_KEY_SIZE];

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    bootloader_random_enable();
    for (size_t i = 0; i < AES_KEY_SIZE; i++)
        buffer[i] = esp_random() & 0xFF;
    bootloader_random_disable();

    mbedtls_ctr_drbg_seed(&ctr_drbg,
                          mbedtls_entropy_func,
                          &entropy,
                          buffer,
                          AES_KEY_SIZE);
}

static void gcm_init(const uint8_t *key)
{
    mbedtls_gcm_free(&gcm);
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, AES_KEY_SIZE * 8);
}
