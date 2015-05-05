/*********************************************************************************
*
*	SPI Sniffer decode


This is a command-line program that reads a coded datastream generated
by an Aduino Mega 2650 and associated circuitry that is acting as
a Sniffer watching SPI communications. We decode and interprets the data
as commands to an RF tranceiver for the Honeywell RedLINK network.

More specifically, we are watching the traffic between the microprocessor on a
Honeywell/Mitsubishi HVAC device (thermostat, temperature sensor, wireless receiver,
etc.) and the TI CC1101 RF transceiver used for the packet-hopping RedLINK
communications.  This program decodes the SPI commands for the CC1101, and also
shows the data of the packets being sent and received. We hope eventually to decode
those packets too.

The datastream generally comes in realtime directly from the USB serial port
on the Arduino, which is mapped on the PC to a virtual COM port. For that,
start the program like this:
   spi_decode -cn
where "n" is the COM port number, which you can get from the Windows
"Devices and Printers" display.

The decoded output is displayed on the console, and also appended to "spi.txt".
The input from the COM port is appended to "spi.dat".

For offline testing, the datastream can also read from the prerecorded "spi.dat"
file. For that, start the program like this:
   spi_decode -f

This decoder is not robust, and will break when it encounters situations I
haven't yet seen. I iterativelly fix problems as they occur. At the moment it is
also dependent on the timing of the line breaks in the datastream from the
Arduino, which could be fixed if it becomes a problem.

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
*/

#define VERSION "1.0"

#define DATFILENAME "spi.dat"  // input in file mode, output in serial mode
#define OUTFILENAME "spi.txt"  // output for decodes

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <time.h>

FILE  *outfile, *datfile;
int comport = 5;
bool fileread = false;

HANDLE handle_serial = INVALID_HANDLE_VALUE;
DCB dcbSerialParams = {
    0};
COMMTIMEOUTS timeouts = {
    0};


/**************  command-line processing  *******************/

void SayUsage(char *programName){
    static char *usage[] = {
        " ",
        "Decode an SPI bytestream to "OUTFILENAME" and the console",
        "Usage: spi_decode [-cn] [-f]",
        "  -cn  inputs from COM port n (default 5) and appends to " DATFILENAME,
        "  -f   inputs from file "DATFILENAME" instead",
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
                // printf("Using COM%d\n", comport);
                break;
            case 'F':
                fileread = true;
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
    if (handle_serial) {
        fprintf(stderr, "\nClosing serial port...");
        if (CloseHandle(handle_serial) == 0)fprintf(stderr, "Error\n");
        else fprintf(stderr, "OK\n");
    }
}

void output (char *fmt, ...) {
    va_list args;
    va_start(args,fmt);
    vfprintf(stdout, fmt, args);
    if (outfile) vfprintf(outfile, fmt, args);
    va_end(args);
}

//**************   TI CC1101 register and command decodes  ******************


#define MAX_LINE 2000
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
    char *name;
    char *descr;
    void (*decode_reg)(void);
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
    ,
    {
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
        "UNUSED 0x3D", ""
    }
    ,	{
        "UNUSED 0x3E", ""
    }
    ,	{
        "UNUSED 0x3F", ""
    }
};

void exit_msg(const char* err) {
    output("**** %s\n", err);
    output(" line %d: %s\n", linecnt, line);
    if (lineptr) output(" error start: %s\n", lineptr);
    cleanup();
    exit(99);
}

void show_config_reg(char *op) {
    output("%s %02X: %s (%s) as %02X ", op, regnum, config_regs[regnum].name, config_regs[regnum].descr, regval);
    if (config_regs[regnum].decode_reg != NULL) (config_regs[regnum].decode_reg)();
    else output("\n");
}

void command_strobe(void) {
    output("command %02X: %s (%s)\n", regnum, command_strobes[regnum-0x30].name, command_strobes[regnum-0x30].descr);
}


void skip_to_next_data(void) {
    while(1) {
        if (*lineptr == 't') {  // timestamp
            unsigned long delta_time;
            if (sscanf(++lineptr, " %ld %n", &delta_time, &num_chars) != 1) exit_msg("bad time format");
            lineptr += num_chars;
            output("pause %ld.%03ld seconds\n", delta_time/1000000, (delta_time % 1000000)/1000);
        }
        else if (*lineptr == ']') {
            chip_selected = false;
            ++lineptr;
        }
        else if (*lineptr == '[') {
            chip_selected = true;
            ++lineptr;
        }
        else if (*lineptr == '.') {
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
}

void read_data_pair(void) {
    if (sscanf(lineptr, " %2hhX/%2hhX %n", &master_data, &slave_data, &num_chars) != 2) {
        exit_msg ("bad hex data");
    }
    lineptr += num_chars;
    // output ("m=%02X, s=%02X\n", master_data, slave_data);
}


int main(int argc,char *argv[]) {
    int argno, i;
    int bytes_bursted, bytes_changed;

    printf("SPI decoder, V%s\n", VERSION);

    argno = HandleOptions(argc,argv);

    if (fileread) {
        if ((datfile = fopen(DATFILENAME,"r")) == NULL) // opne to read from .dat file
            exit_msg(DATFILENAME " open for read failed");
        printf("Reading from" DATFILENAME "\n");
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
            if(SetCommState(handle_serial, &dcbSerialParams) == 0) exit_msg("Error setting serial port parameters");
            timeouts.ReadIntervalTimeout =  100;  		// msec
            timeouts.ReadTotalTimeoutConstant = 0;    // msec
            timeouts.ReadTotalTimeoutMultiplier = 0;  // msec
            timeouts.WriteTotalTimeoutConstant = 50;
            timeouts.WriteTotalTimeoutMultiplier = 10;
            if(SetCommTimeouts(handle_serial, &timeouts) == 0) exit_msg("Error setting serial port timeouts");
            fprintf(stderr,"OK\n");
        }
        else exit_msg("Failed");
        if ((datfile = fopen(DATFILENAME,"a")) == NULL) // open to append to .dat file
            exit_msg(DATFILENAME " open for append failed");
    }

    if ((outfile = fopen(OUTFILENAME,"a")) == NULL) exit_msg(OUTFILENAME " open failed");

    atexit(cleanup);
    printf("Starting\n");

    while(1) {
        if (fileread) { // read from .dat file
            if (!fgets(line, MAX_LINE, datfile)) {
                output("***end of file");
                cleanup();
                exit(0);
            }
            ++linecnt;
            bytes_read = strlen(line);
        }
        else {  // read from serial port
            // printf("reading serial port com%d...\n", comport);
            ReadFile(handle_serial, line, MAX_LINE, &bytes_read, NULL);
            line[bytes_read]='\0';
            if (bytes_read != 0) {
                printf("Got %d bytes from serial port\n", bytes_read);
                // printf("%s\n", line);
                fprintf(datfile, "%s\n", line);
            }
        }
        if (strcmp(line, "SPI Sniffer\n") == 0) {
            printf("\"SPI Sniffer\" header line read\n");
            continue;
        }
        // output("decode %n bytes: %s\n", bytes_read, line);
        lineptr = line;
        while (*lineptr != '\0') {
            skip_to_next_data();  // process input up to next master/slave data pair
            if (*lineptr == '\0') 				break;
            read_data_pair();
            isread = master_data & 0x80; 	// "read register" flag bit
            isburst = master_data & 0x40;	// "burst" flag bit
            regnum = master_data & 0x3f;  	// register number 0 to 63
            if (isread) { //  config register read
                if (regnum >= 0x30 && regnum <= 0x3d && !isburst) { // no, is really command strobe
                    command_strobe();
                }
                else {
                    if(isburst) exit_msg("implement burst read!");
                    skip_to_next_data();
                    read_data_pair();
                    regval = slave_data;
                    show_config_reg("read");
                }
            }
            else { // register write
                if (regnum >= 0x30 && regnum <= 0x3d && !isburst) { // no, is really command strobe
                    command_strobe();
                }
                else if (regnum == 0x3e) { // write power table
                    if (isburst) exit_msg("implement burst power table write");
                    read_data_pair();
                    regval = master_data;
                    show_config_reg("write");
                }
                else if (regnum == 0x3f) { // write TX FIFO
                    if (!isburst) exit_msg("implement non-burst TX FIFO write");
                    if (!chip_selected) exit_msg("burst TX FIFO write without chip selected");
                    show_config_reg("write");
                    while (1) { // show all burst write data to FIFO
                        if (*lineptr == ']') break; // ends with chip unselect
                        read_data_pair();
                        output(" %02X", master_data);
                    }
                    output("\n");
                }
                else {
                    if (isburst) { // burst config register write
                        bytes_bursted = 0;
                        bytes_changed = 0;
                        // output("burst config write\n");
                        if (!chip_selected) exit_msg("burst mode without chip selected");
                        while (1) { // read all burst write data
                            if (*lineptr == ']') break; // ends with chip unselect
                            if (regnum > 0x2e) exit_msg("too much burst data");
                            read_data_pair();
                            new_config_regs[regnum++] = master_data;
                            ++bytes_bursted;
                        }
                        for (regnum=0; regnum<48; ++regnum) {  // show what changed
                            if (new_config_regs[regnum] != current_config_regs[regnum]) {
                                regval = new_config_regs[regnum];
                                show_config_reg(" wrote");
                                current_config_regs[regnum] = new_config_regs[regnum];
                                ++bytes_changed;
                            }
                        }
                        output(" burst wrote %d registers; %d changed\n", bytes_bursted, bytes_changed);
                    }
                    else {  // single register write
                        // skip_to_next_data();
                        if(*lineptr != ']') {
                            read_data_pair();
                            regval = master_data;
                            show_config_reg("write");
                            current_config_regs[regnum] = regval;
                        }
                        else show_config_reg("*** aborted write");
                    }
                }
            }
        }
    }
    return 0;
}
