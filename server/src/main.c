#include <stdio.h>
#include <string.h>

#include "driver/uart.h"
#include "driver/gpio.h"

#include "driver/temperature_sensor.h"

#define UART_PORT UART_NUM_0
#define BUF_SIZE (2 * SOC_UART_FIFO_LEN)

#define LED_GPIO GPIO_NUM_4

temperature_sensor_handle_t temp_handle = NULL;

void uart_init(void)
{
    uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE};

    // Installera UART-drivrutin
    ESP_ERROR_CHECK(uart_driver_install(UART_PORT, BUF_SIZE, 0, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(UART_PORT, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(UART_PORT, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
}

void temp_init(void)
{
    // temperature_sensor_config_t temp_config = {
    //     .range_min = 10,
    //     .range_max = 50,
    // };
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

void app_main(void)
{
    uart_init();
    led_init();
    temp_init();

    uint8_t rx_buf[BUF_SIZE]; // Receive data
    uint8_t tx_buf[BUF_SIZE]; // Send data
    uint8_t led_state = 0;
    float temperature;

    while (1)
    {
        int len = uart_read_bytes(
            UART_PORT,
            rx_buf,
            BUF_SIZE - 1,
            pdMS_TO_TICKS(100));

        if (len > 0)
        {
            rx_buf[strcspn((char *)rx_buf, "\r\n")] = 0;
            rx_buf[len] = '\0';

            if (strcmp((char *)rx_buf, "toggle LED") == 0)
            {
                led_state = !led_state;
                gpio_set_level(LED_GPIO, led_state);
            }
            else if (strcmp((char *)rx_buf, "session closed") == 0)
            {
                led_state = 0;
                gpio_set_level(LED_GPIO, 0);
            }
            else if (strcmp((char *)rx_buf, "temperature") == 0)
            {
                ESP_ERROR_CHECK(temperature_sensor_get_celsius(temp_handle, &temperature));
                int len = snprintf((char *)tx_buf, sizeof(tx_buf), "%.2f\n", temperature);
                printf("Temperature in %f °C\n", temperature);
                // int len = snprintf((char *)tx_buf, sizeof(tx_buf), "32.5\n");
                uart_write_bytes(UART_PORT, tx_buf, len);
            }
        }
    }
}
