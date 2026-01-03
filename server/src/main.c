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

#define LED_GPIO GPIO_NUM_4

#define GET_TEMP_MSG "temperature"
#define TOGGLE_LED_MSG "toggle LED"
#define CLOSE_SESSION_MSG "session closed"

#define SECRET "sadfhj9283ru982iwuh*?sdf_12-3ddq"

#define AES_KEY_SIZE 32
#define IV_SIZE 12
#define TAG_SIZE 16
#define MSG_LEN 32
#define EST_SES_MSG_LEN 40 // Establish session message length (8 bytes for random)
#define SESSION_ID_LEN 8

static uint8_t aes_key[AES_KEY_SIZE]; // Nyckeln. I detta exemplet genereras den av slump
static uint8_t iv[IV_SIZE];           // Nonce
static uint8_t tag[TAG_SIZE];         // Taggen i AES-256-GCM
static uint8_t plaintext[MSG_LEN];    // Meddelandet
static uint8_t ciphertext[MSG_LEN];   // Krypterade meddelandet
static bool session_state = false;    // True om vi har en pågående session

static temperature_sensor_handle_t temp_handle = NULL;

static mbedtls_gcm_context gcm;           // håller AES-256-GCM interna tillstånd
static mbedtls_entropy_context entropy;   // samlar slump
static mbedtls_ctr_drbg_context ctr_drbg; // säker slumpgenerator

void uart_init(void);
void temp_init(void);
void led_init(void);
void random_init(void);
bool get_request(uint8_t *rx_buf);
bool establish_session(uint8_t *rx_buf);
void set_rtc_from_timestamp(uint64_t timestamp_us);

void app_main(void)
{
    uart_init();
    led_init();
    temp_init();
    random_init();

    uart_flush(UART_PORT); // cleaning the buffer from old data

    uint8_t rx_buf[UART_BUF_SIZE]; // Receive data
    uint8_t tx_buf[UART_BUF_SIZE]; // Send data
    uint8_t led_state = 0;
    float temperature;

    while (true)
    {
        size_t RX_FIFO_SIZE;
        uart_get_buffered_data_len(UART_PORT, &RX_FIFO_SIZE);

        if (RX_FIFO_SIZE == 60)
        {
            uart_read_bytes(UART_PORT, rx_buf, 60, 100);
            get_request(rx_buf);
        }
        else if (RX_FIFO_SIZE == 68)
        {
            uart_read_bytes(UART_PORT, rx_buf, 68, 100);
            establish_session(rx_buf);
        }
    }
}

bool establish_session(uint8_t *rx_buf)
{
    bool status = false;
    uint8_t est_ses_plaintext[EST_SES_MSG_LEN];  // Meddelandet
    uint8_t est_ses_ciphertext[EST_SES_MSG_LEN]; // Krypterade meddelandet

    //========================================== FIRST HANDSHAKE BEGINNING ==========================================

    // Bryt ut delarna från meddelandet
    // [IV 12 bytes, cphr 40 bytes, tag 16 bytes]
    memcpy(iv, rx_buf, 12);
    memcpy(est_ses_ciphertext, rx_buf + 12, 40);
    memcpy(tag, rx_buf + 12 + 40, 16);

    // Konvertera SECRET till en uint8_t array
    // char[32] --> uint8_t[32]
    uint8_t SECRET_BYTES[32];
    memcpy(SECRET_BYTES, SECRET, sizeof(SECRET_BYTES));

    // Initiera AES_GCM med SECRET som nyckel
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm,
                       MBEDTLS_CIPHER_ID_AES,
                       SECRET_BYTES,
                       AES_KEY_SIZE * 8);

    // Decrypta meddelandet och spara SESSION_KEY[32] och RAND[8] temporärt lokalt
    uint8_t AAD[8] = {0};
    mbedtls_gcm_auth_decrypt(
        &gcm,
        EST_SES_MSG_LEN,
        iv,
        IV_SIZE,
        AAD,
        sizeof(AAD),
        tag,
        TAG_SIZE,
        est_ses_ciphertext,
        est_ses_plaintext);

    uint8_t aes_key_temp[32];

    // Spara SESSION_KEY temporärt (de 32 första bitarna från est_ses_plaintext)
    memcpy(aes_key_temp, est_ses_plaintext, 32);

    // Spara RAND (de sista 8 bitarna från est_ses_plain_text) i AAD
    memcpy(AAD, est_ses_plaintext + 32, 8);

    // Använd aes_key_temp som nyckeln till AES
    mbedtls_gcm_free(&gcm);
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm,
                       MBEDTLS_CIPHER_ID_AES,
                       aes_key_temp,
                       AES_KEY_SIZE * 8);

    // Generera random SESSION_ID[8] och IV[12]
    uint8_t session_id_temp[SESSION_ID_LEN];
    mbedtls_ctr_drbg_random(&ctr_drbg, session_id_temp, SESSION_ID_LEN);
    mbedtls_ctr_drbg_random(&ctr_drbg, iv, IV_SIZE);

    // Encrtypta meddelandet med SESSION_ID som cipher, RAND som ADD
    mbedtls_gcm_crypt_and_tag(
        &gcm,
        MBEDTLS_GCM_ENCRYPT,
        SESSION_ID_LEN,
        iv,
        IV_SIZE,
        AAD,
        sizeof(AAD),
        session_id_temp, // plaintext msg
        ciphertext,
        TAG_SIZE,
        tag);

    // Skicka (IV, cipher, tag)
    uint8_t response[IV_SIZE + SESSION_ID_LEN + TAG_SIZE]; // 12 + 8 + 16 = 36
    memcpy(response, iv, IV_SIZE);
    memcpy(response + IV_SIZE, ciphertext, SESSION_ID_LEN);
    memcpy(response + IV_SIZE + SESSION_ID_LEN, tag, TAG_SIZE);

    uart_write_bytes(UART_PORT, response, sizeof(response));

    //============================================= FIRST HANDSHAKE END ==========================================

    //========================================== SECOND HANDSHAKE BEGINNING ======================================

    uart_read_bytes(UART_PORT, rx_buf, 36, 100);

    // Bryt ut delarna från meddelandet
    // [IV 12 bytes, cphr 40 bytes, tag 16 bytes]
    memcpy(iv, rx_buf, 12);
    memcpy(est_ses_ciphertext, rx_buf + 12, 8);
    memcpy(tag, rx_buf + 12 + 8, 16);

    // mdebtls har krav att man måste reinitiera GCM varje gång
    mbedtls_gcm_free(&gcm);
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aes_key_temp, AES_KEY_SIZE * 8);

    // Decrypta meddelandet med session_key som nyckel
    uint8_t timestamp[8];

    int ret = mbedtls_gcm_auth_decrypt(
        &gcm,
        8, // plaintext length
        iv,
        IV_SIZE,
        session_id_temp, // AAD = SESSION_ID
        SESSION_ID_LEN,
        tag,
        TAG_SIZE,
        est_ses_ciphertext,
        timestamp);

    if (ret != 0)
    {
        status = false;
    }

    // Konvertera timestamp (big-endian) till en uint64
    uint64_t timestamp_us = 0;
    for (int i = 0; i < 8; i++)
    {
        timestamp_us = (timestamp_us << 8) | timestamp[i];
    }

    // Set RTC till timestamp
    set_rtc_from_timestamp(timestamp_us);

    // Set LED till grön

    // Set session_state till ACTIVE
    session_state = true;

    // Generate random IV
    mbedtls_ctr_drbg_random(&ctr_drbg, iv, IV_SIZE);

    // Enkryptera time_stamp med AES_GCM och använd session_id som AAD
    mbedtls_gcm_free(&gcm);
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aes_key_temp, AES_KEY_SIZE * 8);

    mbedtls_gcm_crypt_and_tag(
        &gcm,
        MBEDTLS_GCM_ENCRYPT,
        sizeof(timestamp), // Storleken på meddelandet som ska skickas
        iv,
        IV_SIZE,
        session_id_temp, // AAD
        sizeof(session_id_temp),
        timestamp, // plaintext msg
        ciphertext,
        TAG_SIZE,
        tag);

    // Skicka (IV, cipher, tag)
    memcpy(response, iv, IV_SIZE);
    memcpy(response + IV_SIZE, ciphertext, sizeof(timestamp));
    memcpy(response + IV_SIZE + sizeof(timestamp), tag, TAG_SIZE);

    uart_write_bytes(UART_PORT, response, sizeof(response));

    //============================================= SECOND HANDSHAKE END =========================================

    status = true; // Ändra så att status kollas och ändras längs funktionen
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
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // Använder ESP hårdvarans slumpgenerator för att skapa en slump nyckel
    bootloader_random_enable();
    for (size_t i = 0; i < AES_KEY_SIZE; i++)
        aes_key[i] = esp_random() & 0xFF;
    bootloader_random_disable();

    // Använder ESP hårdvara random som seed till mbedtls random
    mbedtls_ctr_drbg_seed(&ctr_drbg,
                          mbedtls_entropy_func,
                          &entropy,
                          aes_key,
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