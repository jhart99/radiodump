## Radiodump

A utility for dumping the memory of an AUCTUS A6 based radio such as the COTRE CO01D.  This program tries to implement all of the commands and timing used by the CPS software.

### Usage

To use this you need:
1. Radio
2. Cable (FTDI or CH340 based)
3. Python3 with [pySerial](https://pythonhosted.org/pyserial/) installed

Hook up everything and find your serial port, typically /dev/ttyUSB0.  Run the utility and after 30 seconds the CPS region of the radio will be dumped to stdout

> radiodump.py -p /dev/ttyUSB0 > dumpfile
