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
#define RGB_LED_COLOR_OFF 0, 0, 0

static temperature_sensor_handle_t temp_handle = NULL;

static void led_init(void);
static void temp_init(void);
static bool led_toggle(void);
static float read_temperature(float *temperature);

void app_main(void)
{
    bool status;
    led_init();
    temp_init();
    if (session_init())
    {
        ws2812b_init();
        ws2812b_set_color(RGB_LED_COLOR_RED);

        while (true)
        {

            if (!session_is_active())
            {
                if (session_establish())
                {
                    ws2812b_set_color(RGB_LED_COLOR_GREEN);
                }
            }
            switch (session_get_request())
            {
            case CLOSE_SESSION:
                session_close();
                ws2812b_set_color(RGB_LED_COLOR_RED);
                gpio_set_level(LED_GPIO, LED_OFF);
                break;

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
        }
    }
}

static void temp_init(void)
{
    temperature_sensor_config_t temp_config = TEMPERATURE_SENSOR_CONFIG_DEFAULT(20, 50);

    temperature_sensor_install(&temp_config, &temp_handle);
    // ESP_OK if succeed

    temperature_sensor_enable(temp_handle);
    // ESP_OK Success
    // ESP_ERR_INVALID_STATE if temperature sensor is enabled already.
}

static void led_init(void)
{
    gpio_config_t io_config = {
        .pin_bit_mask = (1ULL << LED_GPIO),
        .mode = GPIO_MODE_INPUT_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE};

    gpio_config(&io_config);
    // ESP_OK success
    // ESP_ERR_INVALID_ARG Parameter error

    gpio_set_level(LED_GPIO, 0);
    // ESP_OK Success
    // ESP_ERR_INVALID_ARG GPIO number error
}

static float read_temperature(float *temperature)
{
    return (ESP_OK == temperature_sensor_get_celsius(temp_handle, temperature));
    /*
    ESP_OK Success
    ESP_ERR_INVALID_ARG invalid arguments
    ESP_ERR_INVALID_STATE Temperature sensor is not enabled yet.
    ESP_FAIL Parse the sensor data into ambient temperature failed (e.g. out of the range).
    */
}

static bool led_toggle(void)
{

    return (ESP_OK == gpio_set_level(LED_GPIO, !gpio_get_level(LED_GPIO)));
    // ESP_OK Success
    // ESP_ERR_INVALID_ARG GPIO number error
}
