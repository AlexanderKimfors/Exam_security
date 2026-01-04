#include <stdio.h>
#include <string.h>

#include <sys/time.h>

#include "driver/uart.h"
#include "driver/gpio.h"

#include "driver/temperature_sensor.h"

#include <esp_random.h>
#include <bootloader_random.h>

#include <mbedtls/gcm.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#define UART_PORT UART_NUM_0
#define UART_BUF_SIZE (2 * SOC_UART_FIFO_LEN)
#define UART_WAIT_TCKS 200

#define LED_GPIO GPIO_NUM_4

#define SECRET "sadfhj9283ru982iwuh*?sdf_12-3ddq"

#define AES_KEY_SIZE 32
#define IV_SIZE 12
#define TAG_SIZE 16
#define SESSION_ID_SIZE 8
#define RAND_SIZE 8
#define TIME_STAMP_SIZE 8
#define MSG_LEN 32 // The size of a message when session is established
#define BYTE_SIZE 8

typedef struct
{
    bool active;
    uint8_t key[AES_KEY_SIZE];
    uint8_t id[SESSION_ID_SIZE];
} session_t;

/*==================== AES_GCM data ========================== */
static uint8_t iv[IV_SIZE];               // Nonce
static uint8_t tag[TAG_SIZE];             // Taggen i AES-256-GCM
static mbedtls_gcm_context gcm;           // håller AES-256-GCM interna tillstånd
static mbedtls_entropy_context entropy;   // samlar slump
static mbedtls_ctr_drbg_context ctr_drbg; // säker slumpgenerator

/*===================== UART data ============================ */
static uint8_t rx_buf[UART_BUF_SIZE]; // Receive data
static uint8_t tx_buf[UART_BUF_SIZE]; // Send data

/*===================== ESP data ============================= */
static temperature_sensor_handle_t temp_handle = NULL;

/*==================== Program data ========================== */
static session_t session;

static void led_init(void);
static void uart_init(void);
static void temp_init(void);
static void random_init(void);
static bool get_request(void);
static bool establish_session(void);
static void gcm_init(const uint8_t *key);
static void set_rtc_from_timestamp(uint64_t timestamp_us);
static bool handle_handshake_1(uint8_t *key, uint8_t *session_id);
static bool handle_handshake_2(uint8_t *key, uint8_t *session_id);

void app_main(void)
{
    uart_init();
    led_init();
    temp_init();
    random_init();

    uart_flush(UART_PORT); // Cleaning the buffer from old data

    uint8_t led_state = 0;
    float temperature;

    while (true)
    {
        size_t RX_FIFO_SIZE;
        uart_get_buffered_data_len(UART_PORT, &RX_FIFO_SIZE);

        if (RX_FIFO_SIZE == (IV_SIZE + MSG_LEN + TAG_SIZE))
        {
            get_request();
        }
        else if (RX_FIFO_SIZE == (IV_SIZE + AES_KEY_SIZE + RAND_SIZE + TAG_SIZE))
        {
            establish_session();
        }
    }
}

static bool establish_session(void)
{
    bool status = false;
    uint8_t aes_key[AES_KEY_SIZE];
    uint8_t session_id[SESSION_ID_SIZE] = {0};
    int ret = 0;
    ret = uart_read_bytes(UART_PORT, rx_buf, IV_SIZE + AES_KEY_SIZE + RAND_SIZE + TAG_SIZE, UART_WAIT_TCKS);

    if (ret == IV_SIZE + AES_KEY_SIZE + RAND_SIZE + TAG_SIZE)
    {
        status = handle_handshake_1(aes_key, session_id);

        if (status)
        {
            ret = uart_read_bytes(UART_PORT, rx_buf, IV_SIZE + TIME_STAMP_SIZE + TAG_SIZE, UART_WAIT_TCKS);

            if (ret == IV_SIZE + TIME_STAMP_SIZE + TAG_SIZE)
            {
                if (handle_handshake_2(aes_key, session_id))
                {
                    status = true;
                }
            }
        }
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

    /* Extract the individual components from the received message */
    memcpy(iv, rx_buf, IV_SIZE);
    memcpy(ciphertext, rx_buf + IV_SIZE, AES_KEY_SIZE + RAND_SIZE);
    memcpy(tag, rx_buf + IV_SIZE + AES_KEY_SIZE + RAND_SIZE, TAG_SIZE);

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
                uint8_t response[IV_SIZE + SESSION_ID_SIZE + TAG_SIZE];
                memcpy(response, iv, IV_SIZE);
                memcpy(response + IV_SIZE, ciphertext, SESSION_ID_SIZE);
                memcpy(response + IV_SIZE + SESSION_ID_SIZE, tag, TAG_SIZE);

                ret = uart_write_bytes(UART_PORT, response, IV_SIZE + SESSION_ID_SIZE + TAG_SIZE);

                if (ret == IV_SIZE + SESSION_ID_SIZE + TAG_SIZE)
                {
                    status = true;
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

    /* Extract the individual components from the received message */
    memcpy(iv, rx_buf, IV_SIZE);
    memcpy(ciphertext, rx_buf + IV_SIZE, TIME_STAMP_SIZE);
    memcpy(tag, rx_buf + IV_SIZE + TIME_STAMP_SIZE, TAG_SIZE);

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
                uint8_t response[IV_SIZE + TIME_STAMP_SIZE + TAG_SIZE];
                memcpy(response, iv, IV_SIZE);
                memcpy(response + IV_SIZE, ciphertext, TIME_STAMP_SIZE);
                memcpy(response + IV_SIZE + TIME_STAMP_SIZE, tag, TAG_SIZE);

                ret = uart_write_bytes(UART_PORT, response, IV_SIZE + TIME_STAMP_SIZE + TAG_SIZE);

                if (ret == IV_SIZE + TIME_STAMP_SIZE + TAG_SIZE)
                {
                    /* Establish session */
                    session.active = true;
                    memcpy(session.id, session_id, SESSION_ID_SIZE);
                    memcpy(session.key, key, AES_KEY_SIZE);
                    status = true;

                    // Set LED to GREEN
                }
            }
        }
    }

    return status;
}

bool get_request(void)
{

    return true;
}

void set_rtc_from_timestamp(uint64_t timestamp_us)
{
    struct timeval tv;

    tv.tv_sec = timestamp_us / 1000000ULL;
    tv.tv_usec = timestamp_us % 1000000ULL;

    settimeofday(&tv, NULL);
}

void temp_init(void)
{
    temperature_sensor_config_t temp_config = TEMPERATURE_SENSOR_CONFIG_DEFAULT(20, 50);
    ESP_ERROR_CHECK(temperature_sensor_install(&temp_config, &temp_handle));
    ESP_ERROR_CHECK(temperature_sensor_enable(temp_handle));
}

void led_init(void)
{
    gpio_config_t io_config = {
        .pin_bit_mask = (1ULL << LED_GPIO),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE};
    gpio_config(&io_config);

    gpio_set_level(LED_GPIO, 0);
}

void random_init(void)
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
void uart_init(void)
{
    uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE};

    // Installera UART-drivrutin
    ESP_ERROR_CHECK(uart_driver_install(UART_PORT, UART_BUF_SIZE, 0, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(UART_PORT, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(UART_PORT, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
}

static void gcm_init(const uint8_t *key)
{
    mbedtls_gcm_free(&gcm);
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, AES_KEY_SIZE * 8);
}
