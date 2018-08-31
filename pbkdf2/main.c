#include "pbkdf2.h"
#include "usb.h"
#include "stm32f4xx.h"
#include "stdbool.h"

// ###########################################
// #########         DEFINES         #########
// ###########################################

#define LED_BLUE GPIO_Pin_15
#define PASSWORD_LENGTH 6

// ###########################################
// #########      DECLARATIONS       #########
// ###########################################

static uint8_t buffer[PASSWORD_LENGTH];
static uint32_t bufferPos;
static bool busy;

static void initLEDs();
void USB_DataReceivedHandler(uint8_t *data, uint32_t len);

// ###########################################
// #########           MAIN          #########
// ###########################################

int main(void)
{
    bufferPos = 0;
    busy = false;

	USB_Init(&USB_DataReceivedHandler);

	initLEDs();

	while (1)
	{
		if (bufferPos == PASSWORD_LENGTH)
		{
			busy = true;
			uint8_t derivedKey[16];

            // blue LED is on as long as the key is generating
			GPIO_SetBits(GPIOD, LED_BLUE);
			pbkdf2(buffer, derivedKey);
			GPIO_ResetBits(GPIOD, LED_BLUE);

            // send derived key and reset input buffer
            USB_SendData(derivedKey, 16);
			bufferPos = 0;
			busy = false;
		}
	}
}

// ###########################################
// #########        FUNCTIONS        #########
// ###########################################

static void initLEDs()
{
	GPIO_InitTypeDef GPIO_InitStructure;

	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOD, ENABLE);

	GPIO_InitStructure.GPIO_Pin = LED_BLUE;
	GPIO_InitStructure.GPIO_Mode = GPIO_Mode_OUT;
	GPIO_InitStructure.GPIO_OType = GPIO_OType_PP;
	GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
	GPIO_Init(GPIOD, &GPIO_InitStructure);
}

// ###########################################
// #########   INTERRUPT HANDLERS    #########
// ###########################################

void USB_DataReceivedHandler(uint8_t *data, uint32_t len)
{
    // 0xFF signals "I am still busy generating a key"
    uint8_t response = 0xFF;

	if (!busy)
	{
        // 0x00 signals "I received data"
		response = 0x00;

		for (int i = 0; (i < len) && (bufferPos < PASSWORD_LENGTH); ++i)
		{
			buffer[bufferPos++] = data[i];
		}
	}

    USB_SendData(&response, 1);
}

