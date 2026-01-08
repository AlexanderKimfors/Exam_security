#include "ws2812b.h"
#include "esp_check.h"
#include "led_strip.h"
#include "freertos/FreeRTOS.h"

static led_strip_handle_t led_strip;
static volatile uint8_t red, green, blue;

static void refresh(void *param)
{
    (void)param;

    while (1)
    {
        ESP_ERROR_CHECK(led_strip_set_pixel(led_strip, 0, red, green, blue));
        ESP_ERROR_CHECK(led_strip_refresh(led_strip));
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

bool ws2812b_init(void)
{
    bool status = false;

    // LED strip general initialization, according to your led board design
    led_strip_config_t strip_config = {
        .strip_gpio_num = GPIO_NUM_8,  // The GPIO that connected to the LED strip's data line
        .max_leds = 1,                 // The number of LEDs in the strip,
        .led_model = LED_MODEL_WS2812, // LED strip model
        // set the color order of the strip: GRB
        .color_component_format = {
            .format = {
                .r_pos = 1,          // red is the second byte in the color data
                .g_pos = 0,          // green is the first byte in the color data
                .b_pos = 2,          // blue is the third byte in the color data
                .num_components = 3, // total 3 color components
            },
        },
        .flags = {
            .invert_out = false, // don't invert the output signal
        }};

    // LED strip backend configuration: SPI
    led_strip_spi_config_t spi_config = {
        .clk_src = SPI_CLK_SRC_DEFAULT, // different clock source can lead to different power consumption
        .spi_bus = SPI2_HOST,           // SPI bus ID
        .flags = {
            .with_dma = false, // Using DMA can improve performance and help drive more LEDs
        }};

    if (ESP_OK == led_strip_new_spi_device(&strip_config, &spi_config, &led_strip))
    {
        status = (pdTRUE == xTaskCreate(refresh, "", 2048, NULL, 0, NULL));
    }

    return status;
}

void ws2812b_set_color(uint8_t _red, uint8_t _green, uint8_t _blue)
{
    red = _red;
    green = _green;
    blue = _blue;
}