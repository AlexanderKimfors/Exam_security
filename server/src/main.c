#include <stdio.h>
#include "session.h"
#include "driver/gpio.h"
#include "driver/temperature_sensor.h"

#define LED_GPIO GPIO_NUM_4

static temperature_sensor_handle_t temp_handle = NULL;

static void led_init(void);
static void temp_init(void);
static void led_toggle(void);
static float read_temperature(void);

void app_main(void)
{
    led_init();
    temp_init();
    session_init();

    while (true)
    {

        if (!session_is_active())
        {
            if (session_establish())
            {
                // Set LED to green
            }
        }

        switch (session_get_request())
        {
        case SESSION_REQ_CLOSE:
            session_close();
            break;

        case SESSION_REQ_GET_TEMP:
            session_send_temperature(read_temperature());
            break;

        case SESSION_REQ_TOGGLE_LED:
            led_toggle();
            break;

        default:
            break;
        }
    }
}

static void temp_init(void)
{
    temperature_sensor_config_t temp_config = TEMPERATURE_SENSOR_CONFIG_DEFAULT(20, 50);
    ESP_ERROR_CHECK(temperature_sensor_install(&temp_config, &temp_handle));
    ESP_ERROR_CHECK(temperature_sensor_enable(temp_handle));
}

static void led_init(void)
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

static float read_temperature(void)
{
    return 0.0f;
}

static void led_toggle(void)
{
}