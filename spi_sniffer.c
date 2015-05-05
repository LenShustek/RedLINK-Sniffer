/*************************************************************************

.      Honeywell RedLINK RF module SPI Sniffer

This program sniffs the communications between the processor and
the TI CC1101 RF transceiver that are inside HVAC modules like the
Honeywell C7089R1013 Wireless Outdoor Sensor

This is written for an Arduino Mega 2650 that is observing the SPI
(Serial Peripheral Interface) control pins output by the processor
as a master: SS, CLK, and MOSI. For that we use the built-in SPI
module in the ATmega2560 chip that is in the Micro.

On the breadboard we also have a 74HCT164 shift register connected to
the MISO serial data signal from the slave to the master, which converts
it to a parallel byte of data connected to an Arduino 8-bit data port.

The output datastream goes in realtime over the Arduino USB serial port
to a program on the PC called spi_decode. which decodes the stream into 
intelligible commands.

The timing here is quite critical, because Honeywell runs the chip fast.
The data clock is 4 Mhz, which is at the limit for a 16 Mhz Arduino.
The idle time between bytes can be as little as 1.5 usec, so the
repetition rate of 8-bit bytes can be as fast as 2+1.5 = 3.5 usec.
And it really does happens that fast when the processor uses burst mode
to initialize all the C1101 control registers. So the inner loop
below has to be decently optimized and have no extraneous processing.

The output is sent over the USB serial port whenever there has
been a long period of inactivity. Wejust hope inactivity will continue
long enough for us to format and send all the data we have buffered.
We do detect when that isn't the case and data has been overrun.
Obviously this is not a general Sniffer-like solution, but it works
well enoough for the way Honeywell communicates with the chip.

The output data stream is in ASCII and has the following elements:

[           slave select has gone high (inactive)
]           slave select has gone low (active)
xx/yy       master/slave data, in hex
tnnnn.\n    long inactivity; it's now nnnn microseconds after the last report
tnnnn!\n    same, but we lost some data due to incoming data while we're sending

--------------------------------------------------------------------------
*   (C) Copyright 2015, Len Shustek
*
*   This program is free software: you can redistribute it and/or modify
*   it under the terms of version 3 of the GNU General Public License as
*   published by the Free Software Foundation at http://www.gnu.org/licenses,
*   with Additional Permissions under term 7(b) that the original copyright
*   notice and author attibution must be preserved and under term 7(c) that
*   modified versions be marked as different from the original.
*
*   This program is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU General Public License for more details.
--------------------------------------------------------------------------

Change log

27 Apr 2015,  L. Shustek,  first version

**************************************************************************/

#define DEBUG 0 // output to Arduino serial console

#include <arduino.h>

// SPI pins are the low four bits of Port B:
//  MISO PB3  // SPI master in slave out (not connected)
//  MOSI PB2  // SPI master out slave in
//  SCK PB1   // SPI clock
//  SS PB0    // SPI slave select

#define MISO_DDR DDRL // for Arduino Mega 2560
#define MISO_PORT PORTL
#define MISO_PINS PINL

#define LED_ON   PORTB |= (1 << PB7) // for Arduino Mega 2560
#define LED_OFF  PORTB &= ~(1 << PB7)
#define LED_FLIP PORTB ^= (1 << PB7)

#define MAX_DATA 250  // max 256, only because index is a byte
#define TIMEOUT 2000  // loops for timeout

byte data_master [MAX_DATA];
byte data_slave [MAX_DATA];
byte data_flag [MAX_DATA];

char string [20];

void setup() {

#if 0 // test code for port D wiring
  MISO_DDR = 0xff; // all bits output
  while (1) {
    for (byte i = 0; i < 255; ++i) MISO_PORT = i;
    LED_FLIP;
  }
#endif

  Serial.begin(115200);
  if (DEBUG) while (!Serial); // wait for console to be started
  Serial.print("SPI Sniffer\n");
  LED_ON;

  DDRB = DDRB &= 0xf0;   // low 4 bits of Port B are inputs: SCK, SS, MOSI, MISO
  MISO_DDR = 0;    // all bits are inputs for th output of shift register that parallizes MISO
  SPCR = (1 << SPE); // enable SPI as slave, not master
}

void loop() {
  unsigned int timer;
  unsigned long time_now, time_before;
  byte last_ss, new_ss;
  byte numbytes, numdbytes;

  timer = 0;
  last_ss = (1 << PB0); // default slave select is high
  numbytes = 0; numdbytes = 0;
  time_before = 0;

  while (1) {
    new_ss = PINB & (1 << PB0); // read slave select (SS) level
    if (new_ss != last_ss) {    // record a slave select change
      if (numbytes < MAX_DATA) data_flag[numbytes++] = new_ss | 0x80;
      last_ss = new_ss;
    }
    if (SPSR & (1 << SPIF)) {  // received a byte
      if (numbytes < MAX_DATA) {
        // read slave data quickly first, since it's not double-buffered
        data_slave[numbytes] = MISO_PINS;  // slave data from external shift register
        data_master[numbytes] = SPDR; // master data from SPI register
        data_flag[numbytes++] = 0;    // no flag means data
      }
      timer = 0;
    }
    else if (++timer > TIMEOUT) { // nothing received after timeout
      // dump the buffer, and hope nothing comes in the meantime
      LED_OFF;
      if (numbytes > 0) {
        for (int i = 0; i < numbytes; ++i) {
          if (data_flag[i] == 0x80) // slave select
            Serial.print('[');
          else if (data_flag[i] == 0x81) { // slave unselect
            Serial.print("] ");
            if (numdbytes > 16) { // extra LF every so often for prettiness
              Serial.println();
              numdbytes = 0;
            }
          }
          else { // data
            sprintf(string, "%02X/%02X ", data_master[i], data_slave[i]);
            Serial.print(string);
            ++numdbytes;
          }
        }
        time_now = micros();
        Serial.print('t');   Serial.print(time_now - time_before);
        time_before = time_now;
        // check for data arrival in the meantime, and indicate if so
        // we're double-buffered, so this might not actually represent a data loss
        Serial.println((SPSR & (1 << SPIF)) ? '!' : '.');
        numbytes = 0;
      }
      timer = 0;
      LED_ON;
    }
  }
}

