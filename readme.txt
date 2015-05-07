The project is to create hardware and software to understand the Honeywell RedLINK wireless HVAC communication, and then build compatible devices.

Honeywell uses (and licenses to Mitsubishi) a proprietary wireless network to communicate among thermostats, temperature sensors, and wireless receivers connected to heating and air condition equipment like fancoils and heat pumps. They do not publicly document the details.

The network is similar to WiFi, but not the same. It is frequency-hopping spread spectrum communication in the 902-926 Mhz band. Data is sent in small packets up to about 30 bytes.

This project is a work in progress, and I will post updates here from time to time. As of 7 May 2015, I've built a Sniffer to decode the traffic between the Honeywell microprocessor in a remote temperature sensor and the TI CC1101 RF transceiver. I see how the chip is configured (and reconfigured when the frequency changes), and I see some examples of packets sent by the sensor.

Here are possible next steps:
 - capture more examples of packets from other devices and try to deduce the format and protocol
 - build a board with an Arduino that controls an RF transceiver and can send and receive commands
   (I'm going to try using the Anaren A1101R09A-EM1 evaluation board)

This is all a leisure-time activity, so it's not clear how quickly I will make more progress.

-- Len