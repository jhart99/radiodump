## Radiodump

A utility for dumping the memory of an AUCTUS A6 based radio such as the COTRE CO01D.  This program tries to implement all of the commands and timing used by the CPS software.

### Usage

To use this you need:
1. Radio
2. Cable (FTDI.  CH340 will work on windows, but not linux because of a [kernel bug](https://patchwork.kernel.org/project/linux-usb/patch/20190608051309.4689-1-jontio@i4free.co.nz/#22974567))
3. Python3 with [pySerial](https://pythonhosted.org/pyserial/) installed and pyserial-asyncio if using the high speed reader

### Slow version
Hook up everything and find your serial port, typically /dev/ttyUSB0.  Run the utility and after 30 seconds the CPS region of the radio will be dumped to stdout

> radiodump.py -p /dev/ttyUSB0 > dumpfile

### Rapid version
Hook up everything and find your serial port, typically /dev/ttyUSB0.
Run the utility, setting the desired range from the command line.  This utility dumps memory *much* faster, but requires asyncio so only will work with an FTDI adapter on linux.

> radiodump2.py -p /dev/ttyUSB0 --begin 0x82000000 --end 0x82400000 > dumpfile
