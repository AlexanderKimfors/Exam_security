#include <string.h>
#include "session.h"
#include <sys/time.h>
#include "communication.h"
#include <stdio.h> // För sscanf i hex to bytes funktionen (kan göra på annat sätt?)

#include <esp_random.h>
#include <bootloader_random.h>

#include <mbedtls/gcm.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include "driver/gpio.h" // Debug

/* Size in bytes */
#define AES_KEY_SIZE 32
#define SESSION_ID_SIZE 8
#define IV_SIZE 12
#define TAG_SIZE 16
#define RAND_SIZE 8
#define TIME_STAMP_SIZE 8
#define REQUEST_SIZE 1

/* Size in bits */
#define BYTE_SIZE 8

#define UART_WAIT_TICKS 200

#define SESSION_TIMEOUT_US (10ULL * 1000000ULL) // ändra 10 till 60

typedef struct
{
    bool active;
    uint8_t key[AES_KEY_SIZE];
    uint8_t id[SESSION_ID_SIZE];
    uint64_t latest_msg; // timestamp from the latest msg
} session_ctx_t;

typedef enum
{
    EXPIRED = -1,
    ERROR = 0,
    OK = 1
} session_status_t;

typedef union
{
    float f;
    uint8_t b[sizeof(float)];
} float_bytes_t;

static session_ctx_t session;
static session_status_t session_status;
static uint8_t iv[IV_SIZE];
static uint8_t tag[TAG_SIZE];
static uint8_t tx_buf[IV_SIZE + SESSION_ID_SIZE + TAG_SIZE];
static uint8_t rx_buf[IV_SIZE + AES_KEY_SIZE + RAND_SIZE + TAG_SIZE];

static mbedtls_gcm_context gcm;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;

static bool random_init(void);
static void gcm_init(const uint8_t *key);
static void set_rtc_from_timestamp(uint64_t timestamp_us);
static bool handle_handshake_1(uint8_t *key, uint8_t *session_id);
static bool handle_handshake_2(uint8_t *key, uint8_t *session_id);
static void hex_to_bytes(const char *hex, uint8_t *out, size_t len);
static bool encrypt_and_send(uint8_t *plaintext, uint8_t *cipher, size_t len, uint8_t *AAD, size_t AAD_len, uint8_t *key);
static inline void write_be64(uint8_t *buf, uint64_t v);
static bool encrypt(uint8_t *plaintext, uint8_t *cipher, size_t msg_len, uint8_t *AAD, size_t AAD_len, uint8_t *key);
static bool send(uint8_t *cipher, size_t len);

bool session_init()
{
    bool status = false;
    session.active = false;
    memset(session.key, 0, AES_KEY_SIZE);
    memset(session.id, 0, SESSION_ID_SIZE);
    if (random_init())
    {
        if (communication_init(SPEED))
        {
            status = true;
        }
    }

    return status;
}

bool session_close(void)
{
    bool status = false;
    int ret;

    uint8_t plaintext[1 + TIME_STAMP_SIZE]; // 1 = sizeof status
    uint8_t cipher[1 + TIME_STAMP_SIZE];    // 1 = status

    // Packa ett plaintext meddelande med [status, timestamp]
    size_t offset = 0;
    plaintext[offset] = session_status;
    offset += 1; // sizeof status
    uint8_t timestamp_b[TIME_STAMP_SIZE];
    write_be64(timestamp_b, session.latest_msg);
    memcpy(plaintext + offset, timestamp_b, TIME_STAMP_SIZE);

    // Generera nytt IV
    if (mbedtls_ctr_drbg_random(&ctr_drbg, iv, IV_SIZE) == 0)
    {
        // Initiera GCM
        gcm_init(session.key);

        // Dekryptera meddelandet
        ret = mbedtls_gcm_crypt_and_tag(
            &gcm,
            MBEDTLS_GCM_ENCRYPT,
            sizeof(plaintext), // Size of the msg
            iv,
            IV_SIZE,
            session.id, // AAD
            SESSION_ID_SIZE,
            plaintext, // Plaintext msg to be encrypted
            cipher,
            TAG_SIZE,
            tag);

        // Packa IV + meddelandet + TAG i ett paket och skicka via uart med timeout
        if (ret == 0)
        {
            offset = 0;
            memcpy(tx_buf, iv, IV_SIZE);
            offset = IV_SIZE;
            memcpy(tx_buf + offset, cipher, sizeof(cipher));
            offset += sizeof(cipher);
            memcpy(tx_buf + offset, tag, TAG_SIZE);

            if (communication_write(tx_buf, IV_SIZE + sizeof(cipher) + TAG_SIZE))
            {
                status = true;
            }
        }
    }

    session.active = false;
    memset(session.key, 0, AES_KEY_SIZE);
    memset(session.id, 0, SESSION_ID_SIZE);
    memset(&session.latest_msg, 0, TIME_STAMP_SIZE);

    mbedtls_gcm_free(&gcm);

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
    uint8_t plain_request[REQUEST_SIZE + TIME_STAMP_SIZE] = {0};
    uint8_t cipher_request[REQUEST_SIZE + TIME_STAMP_SIZE] = {0};

    int len = communication_read(rx_buf, IV_SIZE + REQUEST_SIZE + TIME_STAMP_SIZE + TAG_SIZE);

    if (len == IV_SIZE + REQUEST_SIZE + TIME_STAMP_SIZE + TAG_SIZE)
    {
        size_t offset = 0;
        memcpy(iv, rx_buf + offset, IV_SIZE);
        offset += IV_SIZE;

        memcpy(cipher_request, rx_buf + offset, REQUEST_SIZE + TIME_STAMP_SIZE);
        offset += REQUEST_SIZE + TIME_STAMP_SIZE;

        memcpy(tag, rx_buf + offset, TAG_SIZE);

        gcm_init(session.key);

        int ret = mbedtls_gcm_auth_decrypt(
            &gcm,
            REQUEST_SIZE + TIME_STAMP_SIZE,
            iv,
            IV_SIZE,
            session.id,
            SESSION_ID_SIZE,
            tag,
            TAG_SIZE,
            cipher_request,
            plain_request);
        if (ret != 0)
        {
            req = INVALID;
        }
        else
        {
            /* ================================================================================ */

            /* =================== Extract the request and time from msg ====================== */
            uint64_t time_stamp = 0;

            // memcpy(&req, plain_request, REQUEST_SIZE);
            req = (session_request_t)plain_request[0];

            // memcpy(&time_stamp, plain_request + REQUEST_SIZE, TIME_STAMP_SIZE);

            /* Convert timestamp (big-endian) to uint64 */
            for (int i = 0; i < TIME_STAMP_SIZE; i++)
            {
                time_stamp = (time_stamp << BYTE_SIZE) |
                             plain_request[REQUEST_SIZE + i];
            }

            /* ================================================================================ */

            /* ============================== Validate request ================================ */
            if (time_stamp < session.latest_msg) /* Not valid msg */
            {
                req = INVALID;
            }
            else if ((time_stamp - session.latest_msg) > SESSION_TIMEOUT_US) /* Session expired, close the session */
            {
                session.latest_msg = time_stamp;
                session_status = EXPIRED;
                session_close();
                req = INVALID;
            }
            else if (req == CLOSE_SESSION)
            {
                session.latest_msg = time_stamp;
                session_status = OK;
                session_close();
            }
            else
            {
                session.latest_msg = time_stamp;
            }
            /* ================================================================================ */
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
    uint8_t aes_key[AES_KEY_SIZE];
    uint8_t session_id[SESSION_ID_SIZE] = {0};
    int ret = 0;

    if (handle_handshake_1(aes_key, session_id))
    {
        if (handle_handshake_2(aes_key, session_id))
        {
            status = true;
            session_status = OK;
        }
    }

    return status;
}

bool session_send_temperature(bool temp_status, float temp)
{
    bool status = false;
    int ret;
    size_t offset = 0;
    float_bytes_t fb; // Ta bort?
    fb.f = temp;      // tror jag kan ta bort?

    uint8_t cipher[sizeof(bool) + TIME_STAMP_SIZE + sizeof(float)];
    uint8_t plaintext[sizeof(bool) + TIME_STAMP_SIZE + sizeof(float)];

    uint8_t timestamp_b[TIME_STAMP_SIZE];
    write_be64(timestamp_b, session.latest_msg);

    plaintext[offset] = session_status;
    offset += sizeof(temp_status);
    memcpy(plaintext + offset, timestamp_b, TIME_STAMP_SIZE);
    offset += TIME_STAMP_SIZE;
    memcpy(plaintext + offset, &temp, sizeof(float));

    if (encrypt(plaintext, cipher, sizeof(plaintext), session.id, SESSION_ID_SIZE, session.key))
    {
        status = send(cipher, sizeof(cipher));
    }

    return status;
}

bool session_send_toggle_led(bool status, int state)
{
    int ret;
    size_t offset = 0;

    uint8_t cipher[sizeof(bool) + TIME_STAMP_SIZE + sizeof(bool)];
    uint8_t plaintext[sizeof(bool) + TIME_STAMP_SIZE + sizeof(bool)];

    uint8_t timestamp_b[TIME_STAMP_SIZE];
    write_be64(timestamp_b, session.latest_msg);

    plaintext[0] = status ? OK : ERROR;
    memcpy(plaintext + sizeof(bool), timestamp_b, TIME_STAMP_SIZE);
    plaintext[sizeof(bool) + TIME_STAMP_SIZE] = state;

    if (encrypt(plaintext, cipher, sizeof(plaintext), session.id, SESSION_ID_SIZE, session.key))
    {
        status = send(cipher, sizeof(cipher));
    }

    return status;
}

static bool handle_handshake_1(uint8_t *key, uint8_t *session_id)
{
    bool status = false;
    uint8_t plaintext[AES_KEY_SIZE + SESSION_ID_SIZE];
    uint8_t ciphertext[AES_KEY_SIZE + SESSION_ID_SIZE];
    uint8_t rand[RAND_SIZE];
    int ret = 0;

    int len = communication_read(rx_buf, IV_SIZE + AES_KEY_SIZE + RAND_SIZE + TAG_SIZE);

    if (len == IV_SIZE + AES_KEY_SIZE + RAND_SIZE + TAG_SIZE)
    {
        /* Extract the individual components from the received message */
        size_t offset = 0;
        memcpy(iv, rx_buf + offset, IV_SIZE);
        offset += IV_SIZE;
        memcpy(ciphertext, rx_buf + offset, AES_KEY_SIZE + RAND_SIZE);
        offset += AES_KEY_SIZE + RAND_SIZE;
        memcpy(tag, rx_buf + offset, TAG_SIZE);

        hex_to_bytes(HSECRET, key, AES_KEY_SIZE);

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

            if (encrypt(session_id, ciphertext, SESSION_ID_SIZE, rand, RAND_SIZE, key))
            {
                status = send(ciphertext, SESSION_ID_SIZE);
            }

            return status;
        }
    }

    return status;
}

static bool handle_handshake_2(uint8_t *key, uint8_t *session_id)
{
    bool status = false;
    uint8_t plaintext[TIME_STAMP_SIZE];
    uint8_t ciphertext[TIME_STAMP_SIZE];

    int len = communication_read_timeout(rx_buf, IV_SIZE + TIME_STAMP_SIZE + TAG_SIZE, UART_WAIT_TICKS);
    if (len == (IV_SIZE + TIME_STAMP_SIZE + TAG_SIZE))
    {
        gpio_set_level(GPIO_NUM_4, 1); // debug

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

            if (encrypt(plaintext, ciphertext, TIME_STAMP_SIZE, session_id, SESSION_ID_SIZE, key))
            {
                if (send(ciphertext, TIME_STAMP_SIZE))
                {
                    /* Establish session */
                    session.active = true;
                    session.latest_msg = timestamp_us;
                    memcpy(session.id, session_id, SESSION_ID_SIZE);
                    memcpy(session.key, key, AES_KEY_SIZE);
                    status = true;
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

static bool random_init(void)
{
    uint8_t buffer[AES_KEY_SIZE];

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    bootloader_random_enable();
    for (size_t i = 0; i < AES_KEY_SIZE; i++)
        buffer[i] = esp_random() & 0xFF;
    bootloader_random_disable();

    return !mbedtls_ctr_drbg_seed(&ctr_drbg,
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

static bool encrypt(uint8_t *plaintext, uint8_t *cipher, size_t msg_len, uint8_t *AAD, size_t AAD_len, uint8_t *key)
{
    bool status = false;
    // Generera nytt IV
    if (mbedtls_ctr_drbg_random(&ctr_drbg, iv, IV_SIZE) == 0)
    {
        // Initiera GCM
        gcm_init(key);

        // Dekryptera meddelandet
        if (0 == mbedtls_gcm_crypt_and_tag(
                     &gcm,
                     MBEDTLS_GCM_ENCRYPT,
                     msg_len, // Size of the msg
                     iv,
                     IV_SIZE,
                     AAD, // AAD
                     AAD_len,
                     plaintext, // Plaintext msg to be encrypted
                     cipher,
                     TAG_SIZE,
                     tag))
        {
            status = true;
        }
    }

    return status;
}

static bool send(uint8_t *cipher, size_t len)
{
    size_t offset = 0;
    memcpy(tx_buf, iv, IV_SIZE);
    offset = IV_SIZE;
    memcpy(tx_buf + offset, cipher, len);
    offset += len;
    memcpy(tx_buf + offset, tag, TAG_SIZE);

    return (communication_write(tx_buf, IV_SIZE + len + TAG_SIZE));
}