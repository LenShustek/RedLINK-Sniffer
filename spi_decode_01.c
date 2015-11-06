/*********************************************************************************
*
*		SPI Sniffer decoder
*
*********************************************************************************

This is a command-line program that reads a coded datastream generated
by an Teensy 3.1 microcontroller and associated circuitry that is acting as
a Sniffer watching SPI communications. We decode and interpret the data
as commands to an RF tranceiver for the Honeywell RedLINK network.

More specifically, we are watching the traffic between the microprocessor on a
Honeywell/Mitsubishi HVAC device (thermostat, temperature sensor, wireless receiver,
etc.) and the TI CC1101 RF transceiver used for the packet-hopping RedLINK
communications.  This program decodes the SPI commands for the CC1101, and also
shows the data of the packets being sent and received. We hope eventually to decode
those packets too.

The datastream generally comes in realtime directly from the USB serial port
on the microcontroller, which is mapped on the PC to a virtual COM port.
For that mode, start the program like this:
spi_decode -cn
where "n" is the COM port number, which you can get from the Windows
"Devices and Printers" display.

The detailed decoded output is displayed on the console, and also appended to "spi.cmds.txt".
The packet traffic only is appended to "spi.pkts.txt".
The raw input from the COM port is appended to "spi.dat".

For offline testing, the datastream can also read from a prerecorded "spi.dat" file.
For that, start the program like this:
spi_decode -f

This decoder is not entirely robust, and will break when it encounters situations I
haven't yet seen. I will iterativelly fix problems as they occur.
The major unsolvable issue is that the Sniffer will lose new data while it transmits
a block of recorded data to the PC.

*----------------------------------------------------------------------------------
*   (C) Copyright 2015 Len Shustek
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
*
***********************************************************************************/
/*
* Change log
*
*  1 May 2015, L. Shustek, V1.0
*    - first version
* 11 May 2015, L. Shustek, V1.1
*    - add packet segregation into a separate file
*  7 Jun 2015, L. Shustek, V1.2
*    - implement burst write to the power table, which the thermostat does
* 20 Jun 2015, L. Shustek, V1.3
*    - switch to new input format, enhance error recovery
* 28 Jun 2015, L. Shustek, V1.4
*    - add option to control putting "receive enable" in the packet file
*/

#define VERSION "1.4"

#define DATFILENAME "spi.dat"        // input in file mode, output in serial mode
#define OUTFILENAME "spi.cmds.txt"   // output for detailed decodes
#define PKTFILENAME "spi.pkts.txt"   // output for packets

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <time.h>
#include <conio.h>
typedef unsigned char byte;

FILE  *outfile, *datfile, *pktfile=NULL;
int comport = 5;
bool fileread = false;
bool receive_enable_packet = false;  // useful for investigating the frequency-hopping algorithm

HANDLE handle_serial = INVALID_HANDLE_VALUE;
DCB dcbSerialParams = {
    0};
COMMTIMEOUTS timeouts = {
    0};


#define MAX_PKT 100
struct {
    unsigned long delta_time_usec;
    bool xmit;
    byte length;
    byte data[MAX_PKT];
}
packet;

unsigned long cmd_delta_time = 0;

void packet_decode(void);


/**************  command-line processing  *******************/

void SayUsage(char *programName){
    static char *usage[] = {
        " ",
        "Decode an SPI bytestream to "OUTFILENAME", "PKTFILENAME", and the console",
        "Usage: spi_decode [-cn] [-f]",
        "  -cn  inputs from COM port n (default 5) and appends to " DATFILENAME,
        "  -f   inputs from file "DATFILENAME" instead",
        "  -r   record 'receive enable' in the packet file",
        ""
    };
    int i=0;
    while (usage[i][0] != '\0') fprintf(stderr, "%s\n", usage[i++]);
}

int HandleOptions(int argc,char *argv[]) {
    /* returns the index of the first argument that is not an option; i.e.
    does not start with a dash or a slash*/

    int i,firstnonoption=0;

    /* --- The following skeleton comes from C:\lcc\lib\wizard\textmode.tpl. */
    for (i=1; i< argc;i++) {
        if (argv[i][0] == '/' || argv[i][0] == '-') {
            switch (toupper(argv[i][1])) {
            case 'H':
            case '?':
                SayUsage(argv[0]);
                exit(1);
            case 'C':
                if (sscanf(&argv[i][2],"%d",&comport) != 1 || comport <1 || comport > 20) goto opterror;
                break;
            case 'F':
                fileread = true;
                break;
            case 'R':
                receive_enable_packet = true;
                break;
                /* add more  option switches here */
opterror:
            default:
                fprintf(stderr,"unknown option: %s\n",argv[i]);
                SayUsage(argv[0]);
                exit(4);
            }
        }
        else {
            firstnonoption = i;
            break;
        }
    }
    return firstnonoption;
}

/***************  safe string copy  *****************/

size_t strlcpy(char *dst, const char *src, size_t 	siz) {
    char       *d = dst;
    const char *s = src;
    size_t      n = siz;
    /* Copy as many bytes as will fit */
    if (n != 0)    {
        while (--n != 0)        {
            if ((*d++ = *s++) == '\0')                break;
        }
    }
    /* Not enough room in dst, add NUL and traverse rest of src */
    if (n == 0)    {
        if (siz != 0)            *d = '\0';          /* NUL-terminate dst */
        while (*s++)            ;
    }
    return (s - src - 1);       /* count does not include NUL */
}

/***************  safe string concatenation  *****************/

size_t strlcat(char *dst, const char *src, size_t siz) {
    char       *d = dst;
    const char *s = src;
    size_t      n = siz;
    size_t      dlen;
    /* Find the end of dst and adjust bytes left but don't go past end */
    while (n-- != 0 && *d != '\0')        d++;
    dlen = d - dst;
    n = siz - dlen;
    if (n == 0)        return (dlen + strlen(s));
    while (*s != '\0')    {
        if (n != 1)        {
            *d++ = *s;
            n--;
        }
        s++;
    }
    *d = '\0';
    return (dlen + (s - src));  /* count does not include NUL */
}

void cleanup(void) {
    if (datfile) fclose(datfile);
    if (outfile) fclose(outfile);
    if (pktfile) fclose(pktfile);
    if (handle_serial != INVALID_HANDLE_VALUE) {
        fprintf(stderr, "\nClosing serial port...");
        if (CloseHandle(handle_serial) == 0)fprintf(stderr, "Error\n");
        else fprintf(stderr, "OK\n");
        handle_serial = INVALID_HANDLE_VALUE;
    }
}

void output (char *fmt, ...) {
    va_list args;
    va_start(args,fmt);
    // vfprintf(stdout, fmt, args);
    if (outfile) vfprintf(outfile, fmt, args);
    va_end(args);
}

//**************   TI CC1101 register and command decodes  ******************


#define MAX_LINE 60000
char line[MAX_LINE]={
    0}
, *lineptr;
DWORD bytes_read;
int num_chars, linecnt=0;
unsigned char master_data, slave_data;
bool isread, isburst;
bool chip_selected = false;
unsigned char regnum, regval;

unsigned char current_config_regs[64] = {
    0};
unsigned char new_config_regs[64] = {
    0};

static char *GDO_selection[64] = {
    "RX FIFO filled",
    "RX FIFO filled, or end of packet",
    "TX FIFO filled",
    "TX FIFO full",
    "RX FIFO overflow",
    "TX FIFO overlow",
    "sync word sent/rcvd",
    "packet received",
    "preamble quality reached",
    "clear channel assessment",
    "PLL lock detected",
    "serial clock",
    "serial sync data out",
    "serial data out",
    "carrier sense",
    "CRC ok",
    "?","?","?","?","?","?",
    "RX hard data 1",
    "RX hard data 0",
    "?","?","?",
    "PA_PD",
    "LNA_PD",
    "RX_SYMBOL_TICK",
    "?","?","?","?","?","?",
    "WOR_EVNT0",
    "WOR_EVNT1",
    "CLK_256",
    "CLD-32k",	"?",
    "CHIP_RDYn", "?",
    "XOSC stable", "?","?",
    "high impedance",
    "hardwired to 0",
    "CLK_XOSC/1",
    "CLK_XOSC/1.5",
    "CLK_XOSC/2",
    "CLK_XOSC/3",
    "CLK_XOSC/4",
    "CLK_XOSC/6",
    "CLK_XOSC/8",
    "CLK_XOSC/12",
    "CLK_XOSC/16",
    "CLK_XOSC/24",
    "CLK_XOSC/32",
    "CLK_XOSC/48",
    "CLK_XOSC/64",
    "CLK_XOSC/96",
    "CLK_XOSC/128",
    "CLK_XOSC/192"
};

void decode_IOCFG2 (void) {
    if (regval & 0x40) output("inverted ");
    output("%s\n", GDO_selection[regval & 0x3f]);
}
void decode_IOCFG1 (void) {
    if (regval & 0x80) output("high GDO output strength, ");
    decode_IOCFG2();
}
void decode_IOCFG0 (void) {
    if (regval & 0x80) output("Enable temp sensor, ");
    decode_IOCFG2();
}

static struct {
    char *name;  // config register short name
    char *descr; // config register description
    void (*decode_reg)(void); // extra decoding routine
}
config_regs [64] = {
    {
        "IOCFG2", "GDO2 output pin config", decode_IOCFG2
    }
    ,	{
        "IOCFG1", "GD01 output pin config", decode_IOCFG1
    }
    ,	{
        "IOCFG0", "GDO0 output pin config", decode_IOCFG0
    }
    ,	{
        "FIFOTHR", "FIFO thresholds"
    }
    ,	{
        "SYNC1", "sync word high"
    }
    ,	{
        "SYNC0", "sync word low"
    }
    ,	{
        "PKTLEN", "packet length"
    }
    ,	{
        "PKTCTRL1", "packet control 1"
    }
    ,	{
        "PKTCTRL0", "packet control 0"
    }
    ,	{
        "ADDR", "device address"
    }
    ,	{
        "CHANNR", "channel number"
    }
    ,	{
        "FSCTRL1", "frequency synthesizer control 1"
    }
    ,	{
        "FSCTRL0", "frequency synthesizer control 0"
    }
    ,	{
        "FREQ2", "frequency control word H"
    }
    ,	{
        "FREQ1", "frequency control word M"
    }
    ,	{
        "FREQ0", "frequency control word L"
    }
    ,	{
        "MDMCFRG4", "modem config 4"
    }
    ,	{
        "MDMCFRG3", "modem config 3"
    }
    ,	{
        "MDMCFRG2", "modem config 2"
    }
    ,	{
        "MDMCFRG1", "modem config 1"
    }
    ,	{
        "MDMCFRG0", "modem config 0"
    }
    ,	{
        "DEVIATN", "modem deviation setting"
    }
    ,	{
        "MCSM2", "main radio state machine config 2"
    }
    ,	{
        "MCSM1", "main radio state machine config 1"
    }
    ,	{
        "MCSM0", "main radio state machine config 0"
    }
    ,	{
        "FOCCFG", "frequency offset compensation config"
    }
    ,	{
        "BSCFG", "bit sync config"
    }
    ,    {
        "AGCTRL2", "AGC control 2"
    }
    ,	{
        "AGCTRL1", "AGC control 1"
    }
    ,	{
        "AGCTRL0", "AGC control 0"
    }
    ,	{
        "WOREVT1", "event 0 timeout H"
    }
    ,	{
        "WOREVT0", "event 0 timeout L"
    }
    ,	{
        "WORCTRL", "wake on radio control"
    }
    ,	{
        "FREND1", "front end RX config"
    }
    ,	{
        "FREND0", "front end TX config"
    }
    ,	{
        "FSCAL3", "frequency synthesizer calibration 3"
    }
    ,	{
        "FSCAL2", "frequency synthesizer calibration 2"
    }
    ,	{
        "FSCAL1", "frequency synthesizer calibration 1"
    }
    ,	{
        "FSCAL0", "frequency synthesizer calibration 0"
    }
    ,	{
        "RCCTRL1", "RC oscillator config 1"
    }
    ,	{
        "RCCTRL0", "RC oscillator config 0"
    }
    ,	{
        "FSTEST", "frequency synthesizer calibration control"
    }
    ,	{
        "PTEST", "production test"
    }
    ,	{
        "AGCTEST", "AGC test"
    }
    ,	{
        "TEST2", "test settings 2"
    }
    ,	{
        "TEST1", "test settings 1"
    }
    ,	{
        "TEST0", "test settings 0"
    }
    ,	{
        "UNUSED 0x2F", ""
    }
    ,	{
        "PARTNUM", "part number"
    }
    ,	{
        "VERSION", "version number"
    }
    ,	{
        "FREQEST", "frequency offset estimate"
    }
    ,	{
        "LQI", "demodulator estimate for link quality"
    }
    ,	{
        "RSSI", "received signal strength"
    }
    ,	{
        "MARCSTATE", "control machine state"
    }
    ,	{
        "WORTIME1", "WOR timer H"
    }
    ,	{
        "WORTIME0", "WOR timer L"
    }
    ,	{
        "PKTSTATUS", "GDOx and packet status"
    }
    ,	{
        "VCO_VC_DAC", "PLL calibration module setting"
    }
    ,	{
        "TXBYTES", "underflow, and #bytes in TX FIFO"
    }
    ,	{
        "RXBYTES", "overflow, and #bytes in RX FIFO"
    }
    ,	{
        "RCCTRL1_STATUS", "RC oscillator calibration result 1"
    }
    ,	{
        "RCCTRL0_STATUS", "RC oscillator calibration result 0"
    }
    ,	{
        "PATABLE", "power amp control"
    }
    ,	{
        "FIFO", "data"
    }
}
,
command_strobes [16] = {
    {
        "SRES", "reset chip"
    }
    ,	{
        "SFSTXON", "enable and calibrate"
    }
    ,	{
        "SXOFF", "turn off oscillator"
    }
    ,	{
        "SCAL", "calibrate synthesizer"
    }
    ,	{
        "SRX", "enable RX"
    }
    ,	{
        "STX", "enable TX"
    }
    ,	{
        "SIDLE", "exit TX/RX"
    }
    ,	{
        "UNUSED 0x37", ""
    }
    ,	{
        "SWOR", "start RX polling (wake-on-radio)"
    }
    ,	{
        "SPWD", "enter power down mode"
    }
    ,	{
        "SFRX", "flush RX FIFO"
    }
    ,	{
        "SFTX", "flush TX FIFO"
    }
    ,	{
        "SWORRST", "reset real time clock to Event1"
    }
    ,	{
        "SNOP", "no operation"
    }
    ,	{
        "UNUSED 0x3E", ""
    }
    ,	{
        "UNUSED 0x3F", ""
    }
};


void warn_msg(const char* err, byte parm) {
    output("**** %s, %02X\n", err, parm);
}

void fatal_err(const char *err) {
    fprintf(stderr, err);
    cleanup();
    exit(98);
}

void exit_msg(const char* err, byte parm) {
    int i;
    fprintf(stderr, "**** %s, %02X\n", err, parm);
    output("**** %s, %02X\n", err, parm);
    for (i=0;;++i) {
        if (line[i] == 0) break;
        if (lineptr == &line[i]) output (" <-- error --> ");
        output("%c", line[i]);
    }
    output("\n");
    cleanup();
    exit(99);
}

void show_delta_time(void) {
    if (cmd_delta_time) {
        output("%3ld.%06ld ", cmd_delta_time/1000000, cmd_delta_time % 1000000);
        cmd_delta_time = 0;
    }
    else output("           ");
}


void show_config_reg(char *op, bool burstreg) {
    show_delta_time();
    if (burstreg) output("burst ");
    output("%s %02X: %s (%s) as ", op, regnum, config_regs[regnum].name, config_regs[regnum].descr);
    if (!burstreg) {
        output("%02X ", regval);
        if (config_regs[regnum].decode_reg != NULL) (config_regs[regnum].decode_reg)();
        else output("\n");
    }
}

void command_strobe(void) {
    show_delta_time();
    output("command %02X: %s (%s)\n", regnum, command_strobes[regnum-0x30].name, command_strobes[regnum-0x30].descr);
    if (regnum == 0x30) {  // chip reset: mark in the packet stream
        if (packet.length != 0) exit_msg("reset with packet length not zero", packet.length);
        // not interesting, because it happens too often:  packet_decode();
    }
    if (receive_enable_packet && regnum == 0x34) { // enable RX: create pseudo-packet entry in the log
        fprintf(pktfile, "%3ld.%06d sec ", packet.delta_time_usec/1000000, (packet.delta_time_usec%1000000));
        fprintf(pktfile, "rcv enable on chan %02X sync %02X %02X\n",
            current_config_regs[0x0A], current_config_regs[0x04], current_config_regs[0x05]);
        packet.delta_time_usec = 0;
    }
}

void recover_after_bad_data (char *msg) {
    output ("*** %s at ", msg);
    for (int i=0; i<32 && *(lineptr+i); ++i) output("%c",*(lineptr+i));
    output(", skipping ");
    // try to recover by skipping to next chip select
    while (*lineptr && *lineptr!='[') output("%c", *(lineptr++));
    if (*lineptr=='\0') output("<nul>");
    output(".\n");
}

bool skip_timestamp(void) {
    if (*lineptr == 't') {  // time delta
        unsigned long delta_time;
        if (sscanf(++lineptr, " %ld . %n", &delta_time, &num_chars) != 1) {
            recover_after_bad_data("bad time format");
            return false;
        }
        else {
            lineptr += num_chars;
            cmd_delta_time += delta_time;
            packet.delta_time_usec += delta_time;
        }
    }
    return true;
}


bool skip_to_next_data(void) {
    while(1) {
        if (!skip_timestamp()) return false;
        if (*lineptr == 'w') { // buffer write marker
            int numevents;
            if (sscanf(++lineptr, " %d %n", &numevents, &num_chars) != 1) {
                recover_after_bad_data("bad buffer write numevents format");
                return false;
            }
            else {
                lineptr += num_chars;
                output("received a buffer with %d events\n", numevents);
            }

        }
        else if (*lineptr == ']') {  // chip unselect
            chip_selected = false;
            ++lineptr;
        }
        else if (*lineptr == '[') {  // chip select
            chip_selected = true;
            ++lineptr;
        }
        else if (*lineptr == '.') {  // number end delimeter
            ++lineptr;
        }
        else if (*lineptr == '!') {
            output("*** data lost ***\n");
            ++lineptr;
        }
        else if (*lineptr == ' ' || *lineptr == '\r' || *lineptr == '\n') {
            ++lineptr;
        }
        else break;  // must be master/slave data pair, or end of data
    }
    return true;
}

bool read_data_pair(void) {
    if (!skip_to_next_data()) return false;
    if (sscanf(lineptr, "%2hhX%2hhX %n", &master_data, &slave_data, &num_chars) != 2) {
        recover_after_bad_data("bad hex data");
        return false;
    }
    lineptr += num_chars;
    return true;
}

//****************** packet processing ******************

void packet_decode(void) {
    fprintf(pktfile, "%3ld.%06d sec ", packet.delta_time_usec/1000000, (packet.delta_time_usec%1000000));
    if (packet.length == 0) {  // not really a packet: a chip reset
        fprintf(pktfile, "rset");
    }
    else {
        fprintf(pktfile, "%s %2d bytes chan %02X sync %02X %02X data ",
            packet.xmit ? "sent" : "rcvd", packet.length,
            current_config_regs[0x0A], current_config_regs[0x04], current_config_regs[0x05]);
        if (packet.xmit) fprintf(pktfile, "   "); // align send and received data??
        for (int i=0; i<packet.length; ++i)
            fprintf(pktfile, "%02X ", packet.data[i]);
    }
    fprintf(pktfile, "\n");
    packet.delta_time_usec = 0;
    packet.length = 0;
}


//***************** main loop *************************


int main(int argc,char *argv[]) {
    int argno;

    fprintf(stderr, "SPI decoder, V%s\n", VERSION);

    argno = HandleOptions(argc,argv);

    if (fileread) {
        if ((datfile = fopen(DATFILENAME,"r")) == NULL) // opne to read from .dat file
            fatal_err(DATFILENAME " open for read failed");
        fprintf(stderr, "Reading from " DATFILENAME "\n");
    }
    else {
        char dev_name[80];
        sprintf(dev_name, "\\\\.\\COM%d", comport);
        fprintf(stderr, "Opening serial port on %s...", dev_name);
        handle_serial = CreateFile(dev_name, GENERIC_READ | GENERIC_WRITE, 0, 0,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
        if (handle_serial!=INVALID_HANDLE_VALUE) {
            dcbSerialParams.BaudRate = 115200;
            dcbSerialParams.ByteSize = 8;
            dcbSerialParams.StopBits = ONESTOPBIT;
            dcbSerialParams.Parity = NOPARITY;
            dcbSerialParams.DCBlength = sizeof(DCB);
            if(SetCommState(handle_serial, &dcbSerialParams) == 0) fatal_err("Error setting serial port parameters");
            timeouts.ReadIntervalTimeout =  100;  		// msec
            timeouts.ReadTotalTimeoutConstant = 200;    // msec
            timeouts.ReadTotalTimeoutMultiplier = 0;  // msec
            timeouts.WriteTotalTimeoutConstant = 50;
            timeouts.WriteTotalTimeoutMultiplier = 10;
            if(SetCommTimeouts(handle_serial, &timeouts) == 0) fatal_err("Error setting serial port timeouts");
            fprintf(stderr,"OK\n");
        }
        else fatal_err("Failed");
        if ((datfile = fopen(DATFILENAME,"a")) == NULL) // open to append to .dat file
            fatal_err(DATFILENAME " open for append failed");
    }

    if ((outfile = fopen(OUTFILENAME,"a")) == NULL) fatal_err(OUTFILENAME " open failed");
    if ((pktfile = fopen(PKTFILENAME,"a")) == NULL) fatal_err(PKTFILENAME " open failed");
    fprintf(pktfile, "\n");

    // atexit(cleanup);
    fprintf(stderr, "Starting.\n");

    while(!kbhit()) {
more_data:
        if (fileread) { // read from .dat file
            if (!fgets(line, MAX_LINE, datfile)) {
                output("***end of file");
                fprintf(stderr, "***end of file");
                cleanup();
                exit(0);
            }
            ++linecnt;
            bytes_read = strlen(line);
            output("got %d bytes from the file\n", bytes_read);
        }
        else {  // read from serial port
            // printf("reading serial port com%d...\n", comport);
            ReadFile(handle_serial, line, MAX_LINE, &bytes_read, NULL);
            line[bytes_read]='\0';
            if (bytes_read != 0) {
                output("got %d bytes from serial port\n", bytes_read);
                fprintf(stderr, "got %d bytes from the serial port\n", bytes_read);
                fprintf(datfile, "%s\n", line);
            }
        }

        if (strcmp(line, "SPI Sniffer\n") == 0) {
            fprintf(stderr, "\"SPI Sniffer\" header line read\n");
            continue;
        }
        // output("decode %n bytes: %s\n", bytes_read, line);
        lineptr = line;
        while (*lineptr != '\0') {
            skip_to_next_data();  // process input up to next master/slave data pair
            if (*lineptr == '\0')break;
next_command:
            if (!read_data_pair()) goto more_data;
            isread = master_data & 0x80; 	// "read register" flag bit
            isburst = master_data & 0x40;	// "burst" flag bit
            regnum = master_data & 0x3f;  	// register number 0 to 63

            if (isread) { //  config register read
                if (regnum >= 0x30 && regnum <= 0x3d && !isburst) { // no, is really command strobe
                    command_strobe();
                }
                else {
                    if(isburst){
                        if (regnum == 0x3f) { // read RX FIFO: receive packet
                            if (!chip_selected) exit_msg("burst RX FIFO write without chip selected", regnum);
                            show_config_reg("read", true);
                            packet.xmit = false;
                            while (1) { // show all burst read data from FIFO
                                if (!skip_timestamp()) goto next_command;
                                if (*lineptr == ']') break; // ends with chip unselect
                                if (!read_data_pair()) goto next_command;
                                output(" %02X", slave_data);
                                if (packet.length < MAX_PKT)	{
                                    packet.data[packet.length++] = slave_data;
                                }
                            }
                            output("\n");
                            packet_decode();
                        }
                        else  { // burst read of other than FIFO: consecutive config registers
                            if (!skip_to_next_data()) goto next_command;
                            while (1) {
                                if (!skip_timestamp()) goto next_command;
                                if (*lineptr == ']') break; // ends with chip unselect
                                if (!read_data_pair()) goto next_command;
                                regval = slave_data;
                                show_config_reg("read", false);
                                if (++regnum >= 0x40) exit_msg("burst read of too many config registers", regnum);
                            }
                        }
                    }
                    else { // regular single-register read
                        if (!read_data_pair()) goto next_command;
                        regval = slave_data;
                        show_config_reg("read", false);
                    }
                }
            }
            else { // register write
                if (regnum >= 0x30 && regnum <= 0x3d && !isburst) { // no, is really command strobe
                    command_strobe();
                }
                else if (regnum == 0x3e) { // write power table
                    if (isburst) {
                        if (!chip_selected) exit_msg("burst power table write without chip selected", regnum);
                        show_config_reg("write", true);
                        while (1) { // show all burst write data to power table
                            if (!skip_timestamp()) goto next_command;
                            if (*lineptr == ']') break; // ends with chip unselect
                            if (!read_data_pair()) goto next_command;
                            output(" %02X", master_data);
                        }
                        output("\n");
                    }
                    else { // non-burst write to power table
                        if (!read_data_pair()) goto next_command;
                        regval = master_data;
                        show_config_reg("write", false);
                    }
                }
                else if (regnum == 0x3f) { // write TX FIFO: transmit packet
                    if (!isburst) exit_msg("implement non-burst TX FIFO write", regnum);
                    if (!chip_selected) exit_msg("burst TX FIFO write without chip selected", regnum);
                    show_config_reg("write", true);
                    packet.xmit = true;
                    while (1) { // show all burst write data to FIFO
                        if (!skip_timestamp()) goto next_command;
                        if (*lineptr == ']') break; // ends with chip unselect
                        if (!read_data_pair()) goto next_command;
                        output(" %02X", master_data);
                        if (packet.length < MAX_PKT) {
                            packet.data[packet.length++] = master_data;
                        }
                    }
                    output("\n");
                    packet_decode();
                }
                else { // writing config register(s)
                    if (isburst) { // burst config register write
                        int bytes_bursted, bytes_changed, start_reg, end_reg;
                        bytes_bursted = 0;
                        bytes_changed = 0;
                        start_reg = regnum;
                        // output("burst config write\n");
                        if (!chip_selected) output("burst write without chip selected at reg %02X", regnum);
                        while (1) { // read all the burst write data
                            if (!skip_timestamp()) goto next_command;
                            if (*lineptr == ']') break; // ends with chip unselect
                            if (regnum > 0x2e) exit_msg("too much burst data", regnum);
                            if (!read_data_pair()) goto next_command;
                            new_config_regs[regnum++] = master_data;
                            ++bytes_bursted;
                        }
                        end_reg = regnum-1;
                        for (regnum=start_reg; regnum<end_reg; ++regnum) {  // show only those that changed
                            if ((new_config_regs[regnum] != current_config_regs[regnum])) {
                                regval = new_config_regs[regnum];
                                show_config_reg(" wrote", false);
                                current_config_regs[regnum] = new_config_regs[regnum];
                                ++bytes_changed;
                            }
                        }
                        show_delta_time();
                        output(" burst wrote %d registers, and %d changed\n", bytes_bursted, bytes_changed);
                    }
                    else {  // single register write
                        if (!read_data_pair()) goto next_command;
                        regval = master_data;
                        show_config_reg("write", false);
                        current_config_regs[regnum] = regval;
                    }
                }
            }
        }
    }
    return 0;
}
