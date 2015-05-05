Hardware and software to capture and decode the Honeywell RedLINK wireless HVAC communication.

Honeywell uses (and licenses to Mitsubishi) a proprietary wireless network to communicate among thermostats, temperature sensors, and wireless receivers connected to heating and air condition equipment like fancoils and heat pumps. 

This network is like wifi, but not the same. It is frequency-hopping spread spectrum communication in the 902-926 Mhz band. Data is sent in small packets up to 30 bytes.

The project is a work in progress, and I will post updates here from time to time. As of 5 May 2015, I've built a Sniffer to decode the traffic between the Honeywell microprocessor in a remote temperature sensor and the TI CC1101 RF transceiver. I see how the chip is configured (and reconfigured when the frequency changes), and I see some examples of packets sent by the sensor.

Here are possible next steps:
 - see more traffic to try to deduce the frequency-hopping algorithm
 - capture more examples of packets from other devices and deduce the format
 - build a board with an Arduino that controls an RF transceiver
   (I'm going to try using the Anaren A1101R09A-EM1 evaluation board)

This is all a leisure-time activity, so it's not clear how quickly I will make more progress.

-- Len