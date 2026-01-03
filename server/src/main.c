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

#define GET_TEMP_MSG "temperature"
#define TOGGLE_LED_MSG "toggle LED"
#define CLOSE_SESSION_MSG "session closed"

#define SECRET "sadfhj9283ru982iwuh*?sdf_12-3ddq"

#define AES_KEY_SIZE 32
#define IV_SIZE 12
#define TAG_SIZE 16
#define AAD_SIZE 8
#define MSG_LEN 32
#define SESSION_ID_LEN 8
#define HANDSHAKE_1_MSG_SIZE (AES_KEY_SIZE + AAD_SIZE)
#define HANDSHAKE_2_MSG_SIZE 8

#define REQ_MSG_SIZE (IV_SIZE + MSG_LEN + TAG_SIZE)
#define EST_SES_MSG_SIZE (IV_SIZE + MSG_LEN + TAG_SIZE + SESSION_ID_LEN)

typedef struct
{
    bool active;
    uint8_t session_key[AES_KEY_SIZE];
    uint8_t session_id[SESSION_ID_LEN];
} session_t;

// AES_GCM data
static uint8_t iv[IV_SIZE];   // Nonce
static uint8_t tag[TAG_SIZE]; // Taggen i AES-256-GCM
// static uint8_t plaintext[MSG_LEN];        // Meddelandet
// static uint8_t ciphertext[MSG_LEN];       // Krypterade meddelandet
static mbedtls_gcm_context gcm;           // håller AES-256-GCM interna tillstånd
static mbedtls_entropy_context entropy;   // samlar slump
static mbedtls_ctr_drbg_context ctr_drbg; // säker slumpgenerator

// UART data
static uint8_t rx_buf[UART_BUF_SIZE]; // Receive data
static uint8_t tx_buf[UART_BUF_SIZE]; // Send data

// ESP data
static temperature_sensor_handle_t temp_handle = NULL;

// Program data
static session_t session;

static void uart_init(void);
static void temp_init(void);
static void led_init(void);
static void random_init(void);
static bool get_request();
static bool establish_session();
static void set_rtc_from_timestamp(uint64_t timestamp_us);
static void gcm_init(const uint8_t *key);
static bool handle_handshake_1(uint8_t *key, uint8_t *AAD, uint8_t *session_id);
static bool handle_handshake_2(uint8_t *key, uint8_t *AAD, uint8_t *session_id);

void app_main(void)
{
    uart_init();
    led_init();
    temp_init();
    random_init();

    uart_flush(UART_PORT); // cleaning the buffer from old data

    uint8_t led_state = 0;
    float temperature;

    while (true)
    {
        size_t RX_FIFO_SIZE;
        uart_get_buffered_data_len(UART_PORT, &RX_FIFO_SIZE);

        if (RX_FIFO_SIZE == REQ_MSG_SIZE)
        {
            get_request();
        }
        else if (RX_FIFO_SIZE == EST_SES_MSG_SIZE)
        {
            establish_session();
        }
    }
}

bool establish_session()
{
    bool status = true;
    uint8_t aes_key[AES_KEY_SIZE];
    uint8_t AAD[AAD_SIZE] = {0};
    uint8_t session_id[SESSION_ID_LEN];
    int ret = 0;

    ret = uart_read_bytes(UART_PORT, rx_buf, EST_SES_MSG_SIZE, UART_WAIT_TCKS);

    if (ret == EST_SES_MSG_SIZE)
    {
        status = handle_handshake_1(aes_key, AAD, session_id);

        if (status)
        {

            ret = uart_read_bytes(UART_PORT, rx_buf, IV_SIZE + HANDSHAKE_2_MSG_SIZE + TAG_SIZE, UART_WAIT_TCKS);

            if (ret == IV_SIZE + HANDSHAKE_2_MSG_SIZE + TAG_SIZE)
            {
                handle_handshake_2(aes_key, AAD, session_id);

                status = true; // Ändra så att status kollas och ändras längs funktionen
            }
        }
    }
    return status;
}

bool get_request(uint8_t *rx_buf)
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
    uint8_t buffer[32];

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // Använder ESP hårdvarans slumpgenerator för att skapa en slump nyckel
    bootloader_random_enable();
    for (size_t i = 0; i < AES_KEY_SIZE; i++)
        buffer[i] = esp_random() & 0xFF;
    bootloader_random_disable();

    // Använder ESP hårdvara random som seed till mbedtls random
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

static bool handle_handshake_1(uint8_t *key, uint8_t *AAD, uint8_t *session_id)
{
    bool status = false;
    uint8_t plaintext[HANDSHAKE_1_MSG_SIZE];
    uint8_t ciphertext[HANDSHAKE_1_MSG_SIZE];
    int ret = 0;

    // Bryt ut delarna från meddelandet
    // [IV 12 bytes, cphr 40 bytes, tag 16 bytes]
    memcpy(iv, rx_buf, IV_SIZE);
    memcpy(ciphertext, rx_buf + IV_SIZE, HANDSHAKE_1_MSG_SIZE);
    memcpy(tag, rx_buf + IV_SIZE + HANDSHAKE_1_MSG_SIZE, TAG_SIZE);

    // Konvertera SECRET till en uint8_t array
    // char[32] --> uint8_t[32]
    memcpy(key, SECRET, AES_KEY_SIZE);

    // Initiera AES_GCM med SECRET som nyckel
    gcm_init(key);

    ret = mbedtls_gcm_auth_decrypt(
        &gcm,
        HANDSHAKE_1_MSG_SIZE,
        iv,
        IV_SIZE,
        AAD,
        AAD_SIZE,
        tag,
        TAG_SIZE,
        ciphertext,
        plaintext);

    if (ret == 0)
    {
        // Spara SESSION_KEY temporärt (de 32 första bitarna från plaintext)
        memcpy(key, plaintext, AES_KEY_SIZE);

        // Spara RAND (de sista 8 bitarna från est_ses_plain_text) i AAD
        memcpy(AAD, plaintext + AES_KEY_SIZE, AAD_SIZE);

        // Använd aes_key_temp som nyckeln till AES
        gcm_init(key);

        // Generera random SESSION_ID[8] och IV[12]
        mbedtls_ctr_drbg_random(&ctr_drbg, session_id, SESSION_ID_LEN);
        mbedtls_ctr_drbg_random(&ctr_drbg, iv, IV_SIZE);

        // Encrtypta SESSION_ID
        ret = mbedtls_gcm_crypt_and_tag(
            &gcm,
            MBEDTLS_GCM_ENCRYPT,
            SESSION_ID_LEN,
            iv,
            IV_SIZE,
            AAD,
            AAD_SIZE,
            session_id, // plaintext msg
            ciphertext,
            TAG_SIZE,
            tag);

        if (ret == 0)
        {
            // Skicka (IV, cipher, tag)
            uint8_t response[IV_SIZE + SESSION_ID_LEN + TAG_SIZE]; // 12 + 8 + 16 = 36
            memcpy(response, iv, IV_SIZE);
            memcpy(response + IV_SIZE, ciphertext, SESSION_ID_LEN);
            memcpy(response + IV_SIZE + SESSION_ID_LEN, tag, TAG_SIZE);

            ret = uart_write_bytes(UART_PORT, response, IV_SIZE + SESSION_ID_LEN + TAG_SIZE);

            if (ret == IV_SIZE + SESSION_ID_LEN + TAG_SIZE)
            {
                status = true;
            }
        }
    }
    return status;
}

static bool handle_handshake_2(uint8_t *key, uint8_t *AAD, uint8_t *session_id)
{
    bool status = false;
    uint8_t plaintext[HANDSHAKE_2_MSG_SIZE];
    uint8_t ciphertext[HANDSHAKE_2_MSG_SIZE];

    // Bryt ut delarna från meddelandet
    // [IV 12 bytes, cphr 40 bytes, tag 16 bytes]
    memcpy(iv, rx_buf, IV_SIZE);
    memcpy(ciphertext, rx_buf + IV_SIZE, HANDSHAKE_2_MSG_SIZE);
    memcpy(tag, rx_buf + IV_SIZE + HANDSHAKE_2_MSG_SIZE, TAG_SIZE);

    // mdebtls har krav att man måste reinitiera GCM varje gång
    gcm_init(key);

    // Decrypta meddelandet med session_key som nyckel
    int ret = mbedtls_gcm_auth_decrypt(
        &gcm,
        HANDSHAKE_2_MSG_SIZE,
        iv,
        IV_SIZE,
        session_id, // AAD
        SESSION_ID_LEN,
        tag,
        TAG_SIZE,
        ciphertext,
        plaintext);

    if (ret == 0)
    {
        // Konvertera timestamp (big-endian) till en uint64
        uint64_t timestamp_us = 0;
        for (int i = 0; i < 8; i++)
        {
            timestamp_us = (timestamp_us << 8) | plaintext[i];
        }

        // Set RTC till timestamp
        set_rtc_from_timestamp(timestamp_us);

        // Set LED till grön

        // init session
        session.active = true;
        memcpy(session.session_id, session_id, SESSION_ID_LEN);
        memcpy(session.session_key, key, AES_KEY_SIZE);

        // Generate random IV
        if (mbedtls_ctr_drbg_random(&ctr_drbg, iv, IV_SIZE) == 0)
        {
            // Enkryptera time_stamp med AES_GCM och använd session_id som AAD
            gcm_init(session.session_key);

            ret = mbedtls_gcm_crypt_and_tag(
                &gcm,
                MBEDTLS_GCM_ENCRYPT,
                HANDSHAKE_2_MSG_SIZE, // Storleken på meddelandet som ska skickas
                iv,
                IV_SIZE,
                session_id, // AAD
                SESSION_ID_LEN,
                plaintext, // received timestamp
                ciphertext,
                TAG_SIZE,
                tag);

            if (ret == 0)
            {
                // Skicka (IV, cipher, tag)
                uint8_t response[IV_SIZE + HANDSHAKE_2_MSG_SIZE + TAG_SIZE];
                memcpy(response, iv, IV_SIZE);
                memcpy(response + IV_SIZE, ciphertext, HANDSHAKE_2_MSG_SIZE);
                memcpy(response + IV_SIZE + HANDSHAKE_2_MSG_SIZE, tag, TAG_SIZE);

                ret = uart_write_bytes(UART_PORT, response, IV_SIZE + HANDSHAKE_2_MSG_SIZE + TAG_SIZE);

                if (ret == IV_SIZE + HANDSHAKE_2_MSG_SIZE + TAG_SIZE)
                {
                    status = true;
                }
            }
        }
    }

    return status;
}