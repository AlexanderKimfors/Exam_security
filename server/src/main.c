#include <stdio.h>
#include "session.h"
#include "ws2812b.h"
#include "driver/gpio.h"
#include "driver/temperature_sensor.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define LED_GPIO GPIO_NUM_4
#define LED_ON 1
#define LED_OFF 0

#define RGB_LED_COLOR_RED 255, 0, 0
#define RGB_LED_COLOR_GREEN 0, 255, 0
#define RGB_LED_COLOR_BLUE 0, 0, 255

static temperature_sensor_handle_t temp_handle = NULL;

static bool led_init(void);
static bool temp_init(void);
static bool led_toggle(void);
static bool read_temperature(float *temperature);

void app_main(void)
{
    bool status = led_init() && temp_init() && session_init() && ws2812b_init();

    if (!status)
    {
        while (true)
        {
            // Initilization whent wrong, do not continut.
        }
    }
    ws2812b_set_color(RGB_LED_COLOR_GREEN);

    while (true)
    {
        if (!session_is_active())
        {
            if (!session_establish())
            {
                ws2812b_set_color(RGB_LED_COLOR_RED);
            }
        }

        if (session_is_active())
        {
            switch (session_get_request())
            {
            case GET_TEMP:
                float temp;
                status = read_temperature(&temp);
                session_send_temperature(status, temp);
                break;

            case TOGGLE_LED:
                status = led_toggle();
                session_send_toggle_led(status, gpio_get_level(LED_GPIO));
                break;

            case INVALID:
                break;

            default:
                break;
            }

            if (!status)
            {
                ws2812b_set_color(RGB_LED_COLOR_RED);
            }
            else
            {
                ws2812b_set_color(RGB_LED_COLOR_GREEN);
            }
        }
    }
}

static bool temp_init(void)
{
    bool status = false;

    temperature_sensor_config_t temp_config = TEMPERATURE_SENSOR_CONFIG_DEFAULT(20, 50);

    if (ESP_OK == temperature_sensor_install(&temp_config, &temp_handle))
    {
        if (ESP_OK == temperature_sensor_enable(temp_handle))
        {
            status = true;
        }
    }

    return status;
}

static bool led_init(void)
{
    bool status = false;

    gpio_config_t io_config = {
        .pin_bit_mask = (1ULL << LED_GPIO),
        .mode = GPIO_MODE_INPUT_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE};

    if (ESP_OK == gpio_config(&io_config))
    {
        if (ESP_OK == gpio_set_level(LED_GPIO, 0))
        {
            status = true;
        }
    }

    return status;
}

static bool read_temperature(float *temperature)
{
    return (ESP_OK == temperature_sensor_get_celsius(temp_handle, temperature));
}

static bool led_toggle(void)
{

    return (ESP_OK == gpio_set_level(LED_GPIO, !gpio_get_level(LED_GPIO)));
}
