/*************************************************************************

.          SPI Sniffer
   for Honeywell RedLINK RF modules and other stuff

This program records the communication on an SPI (Serial Peripheral Interface)
bus. (See https://en.wikipedia.org/wiki/Serial_Peripheral_Interface_Bus )
We use a combination of a commercial Arduino-like microprocessor and 
custom hardware.

We are specifically interested in the communication between the processor
and the TI CC1101 RF transceiver that are inside HVAC modules like the
Honeywell C7089R1013 Wireless Outdoor Sensor.

But there is nothing in this code or in the hardware that is specific to 
the Honeywell devices, so it might be useful as a general SPI Sniffer.

The output datastream goes over a USB serial port to a program on a PC. 
Our such program, called spi_decode. decodes the stream into intelligible 
commands for the TI RF chip, so that part *is* specific to our application.

This is written for a 96Mhz  Teensy 3.1 that connected to custom hardware
that has two shift registers to record the SPI MOSI and MISO data, plus
some control and timing logic. It has four ICs.

(I initially tried using the SPI module of the Freescale MK20DX chip that
is on the Teensy to record the SPI Master data, but there was too much
jitter in the presentation of the data relative to the SS (slave select)
signal, and it is important to have that timing information to decode
the data.)

The timing here is quite critical, because Honeywell runs the chip 
really fast. The SPI data clock can be as high as 6 Mhz.
The idle time between bytes can be as little as 1 usec, so the
repetition rate of 8-bit bytes can be as fast as 1.3+1 = 2.3 usec.
It really does happens that fast when the processor uses burst mode
to initialize all the C1101 control registers, so the inner loop
below has to be decently optimized and have no extraneous processing.

The output is sent over the USB serial port whenever there has
been a long period of inactivity, or when the buffer is full. 
If there is lots of constant SPI bus activity, data loss is inevitable.

The output data stream is in ASCII and has the following elements:

[           slave select has gone low (active)
]           slave select has gone high (inactive)
xxyy        master (xx) and slave (yy) data, in hex
tnnnn.      timestamp: it's now nnnn microseconds after the last report
\n          newline every so often, for prettiness

The output is decoded and interpreted on the PC by the spi_decode program.

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

27 Apr 2015,  L. Shustek, V1.0  First version
19 May 2015,  L. Shustek, V2.0  Switch to Teensy 3.1 because we need more speed
26 May 2015,  L. Shustek, V3.0  Use both SPI modules in the Teensy, so we don't
                                need the external shift register any more.
20 Jun 2015,  L. Shustek, V4.0  That doesn't work: the 2nd SPI module isn't really
                                there (a Freescale documentation error!), and 
                                anyway there's too much delay in their modules.
                                So we switch to collecting all the SPI data with
                                external hardware.

**************************************************************************/

#define TEST 0

#include <arduino.h>
#include <SPI.h>

#define DATA_IN GPIOD_PDIR  // MOSI and MISO data lines are wired to shift registers on port D

#define INPUT_SELECT 9  // output: controls which shift register to read: HIGH is MOSI, LOW is MISO
                        // when it goes low, it also resets "data ready" flipflop
#define DATA_READY 11  // input: data is ready
#define SSNOT 12  // input: slave not selected

#define MAX_DATA 7000  // (max 254 if the index is a byte)
#define TIMEOUT 100000  // loops for timeout; at 96 Mhz, a few tens of milliseconds

byte data_master [MAX_DATA + 2];
byte data_slave [MAX_DATA + 2];
byte data_flag [MAX_DATA + 2];
unsigned long data_timestamp [MAX_DATA + 2]; // timestamp every slave select change

char string [20];

void setup() {
  Serial.begin(115200);
#if TEST 
  while (!Serial) ; // wait for PC serial port to start
  Serial.print("SPI Sniffer starting.\n");
  for (int i = 0; i < 5; ++i) {
    Serial.println(i + 1);
    delay(1000);
  }
#endif

  pinMode(INPUT_SELECT, OUTPUT);
  pinMode(DATA_READY, INPUT);
  pinMode(SSNOT, INPUT);
  digitalWriteFast(INPUT_SELECT, HIGH);  // select master data, don't clear ready

  pinMode(2, INPUT);    // port D bits are the outputs of the data shift registers
  pinMode(14, INPUT);
  pinMode(7, INPUT);
  pinMode(8, INPUT);
  pinMode(6, INPUT);
  pinMode(20, INPUT);
  pinMode(21, INPUT);
  pinMode(5, INPUT);
}

unsigned long delta; // TEMP

void loop() {
  unsigned long timer;
  unsigned long time_now, time_before;
  byte last_ss, new_ss;
  unsigned int numbytes, numdbytes;

#if 0 // scope timing loop: takes about 0.814 usec per loop at 96 Mhz, so micros() is pretty fast!
  { byte toggle = 0;
    pinMode(3, OUTPUT);
    while (1) {
      time_now = micros(); // record timestamp
      delta = time_now - time_before;
      time_before = time_now;
      //toggle ^= 1;
      //digitalWriteFast(3, toggle);
      digitalWriteFast(3, HIGH);
      asm("nop\n nop\n nop\n nop");  //at 96 Mhz, 50 nsec pulse every 400 nsec
      digitalWriteFast(3, LOW);
    }
  }
#endif

  timer = 0;
  last_ss = 1; // default slave select is high
  numbytes = 0; numdbytes = 0;
  time_before = micros();

  // We buffer up bytes and slave select changes while they happen, fast, without
  // sending anything to the host. When there's a pause or our buffer overflows, send it all.

  while (1) {  // The timing is tricky. Here be race conditions!

    if (digitalReadFast(DATA_READY)) {  // transfer complete: received a byte
      if (numbytes < MAX_DATA) {
        data_master[numbytes] = (byte) DATA_IN; // read master data from shift register
        digitalWriteFast(INPUT_SELECT, LOW); // start switch to reading slave data, and reset ready
        data_flag[numbytes++] = 0;    // no flag means data
        asm("nop\n nop\n nop\n nop"); // make sure we wait at least 50 ns
        data_slave[numbytes] = (byte) DATA_IN; // now read slave data from shift register
        digitalWriteFast(INPUT_SELECT, HIGH); // return to reading master data for next time
      }
      timer = 0;
    }

    new_ss = digitalReadFast(SSNOT); // read slave select (SS) level
    if (new_ss != last_ss) {    // if slave select changed, record it now
      if (numbytes < MAX_DATA) {
        if (new_ss == 0) {  // if this is "select" (low)
          time_now = micros(); // then also record a timestamp
          data_timestamp[numbytes] = time_now - time_before;
          time_before = time_now;
        }
        data_flag[numbytes++] = new_ss | 0x80;
      }
      last_ss = new_ss;
    }

    if (++timer > TIMEOUT  // nothing received after timeout
        || numbytes >= MAX_DATA) { // or our buffer is full
      if (numbytes > 0) { // write the buffer
        Serial.print('w'); Serial.print(numbytes); Serial.print('.');  // mark buffer write
        for (unsigned int i = 0; i < numbytes; ++i) {

          if (data_flag[i] == 0x80) { // slave select, which also has a timestamp
            Serial.print('t'); Serial.print(data_timestamp[i]); Serial.print(".[");
          }
          else if (data_flag[i] == 0x81) { // slave unselect
            Serial.print(']');
            if (numdbytes > 16) { // extra LF every so often after deselect, for prettiness
              Serial.println();
              numdbytes = 0;
            }
          }
#if 0 // currently not implemented
          else if (data_flag[i] == 0x82) {
            Serial.print('!');
          }
#endif
          else { // data
            sprintf(string, "%02X%02X", data_master[i], data_slave[i]);
            Serial.print(string);
            ++numdbytes;
          }
        } // for all bytes
        numbytes = 0;
      }
      timer = 0;
    }
  }
}

