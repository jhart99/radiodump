#!/usr/bin/env python3
"""Player for general text log files."""

import serial
import binascii
import time
import struct
import sys
import functools
import operator

__author__ = "jhart99"
__license__ = "MIT"

def eprint(*args, **kwargs):
    """ print to stderr

    This function takes its arguments just as if it were the normal
    print function and instead prints to stderr.

    """

    print(*args, file=sys.stderr, **kwargs)

def compute_check(msg):
    """ Compute the check value for a message

    AUCTUS messages use a check byte which is simply the XOR of all
    the values of the message.

    """

    if len(msg) == 0:
        return 0
    return functools.reduce(operator.xor, msg)

def format_frame(message):
    """ Format a raw message into a frame

    AUCTUS frames are of the form AD 00 XX FF ...message... YY
    where XX is the length of the message and YY is the check byte
    Additionally certain bytes in the message are escaped.

    """

    header = bytes([0xad, 0x00])
    begin = bytes([0xff])
    msg = begin + message
    msglen = bytes([len(msg)])
    check = bytes([compute_check(msg)])
    return escaper(header + msglen + msg + check)

def readFrame(addr, seq = 1):
    """ make a frame to read a word at a memory address

    this function creates a frame to read the memory from the device
    suitable for serial transmission.

    """

    command = 0x02
    msg = struct.pack('<BIB', command, addr, seq)
    return format_frame(msg)

def magicFrame(content):
    """ make a frame containing magic(an unknown command)

    this function creates a frame to do some device magic and these
    frames are used in the preamble and finalizer commands.

    """

    command = bytes([0x84])
    msg = command + content
    return format_frame(msg)

def writeFrame(addr, content):
    """ make a frame containing a write command

    this function creates a frame to do write a multiple byte content
    at a specific memory address.  The length need not be a word, but
    could be 16 bytes or more.

    """

    command = bytes([0x83])
    addr = struct.pack('<I', addr)
    msg = command + addr + content
    return format_frame(msg)

def knockFrame():
    """ make a frame containing a knock command

    this function creates a frame that I assume wakes up the device
    for further commands.

    """

    command = bytes([0x04])
    content = bytes([0x03, 0x00, 0x00, 0x00, 0x01])
    msg = command + content
    return format_frame(msg)

def escaper(msg):
    """ escape message

    this function escapes special characters in the message.  These
    are 0x5c, 0x11 and 0x13 which are '\' and XON and XOFF characters.

    """

    out = bytes(sum([[0x5c, 0x5c ^ x ^ 0xa3] if x in [0x11, 0x13, 0x5c] else [x] for x in msg], []))
    return out

def unescaper(msg):
    """ unescape message

    this function undoes any escape sequences in a received message
    """

    out = []
    escape = False
    for x in msg:
        if x == 0x5c:
            escape = True
            continue
        if escape:
            x = 0x5c ^ x ^ 0xa3
            escape = False
        out.append(x)
    return bytes(out)

def waitonread(sio, retries=256, delay=0, verbosity = 0):
    """ Wait until a read happens

    This function waits until something is received from the serial or
    will abort after a certain number of retries.
    """

    size = sio.in_waiting
    countdown = retries
    while size == 0 and countdown > 0:
        size = sio.in_waiting
        countdown -= 1
        if delay: time.sleep(delay)
    if countdown == 0:
        # nothing received
        return b''
    if size > 0:
        data = sio.read(size)
        if verbosity: eprint(">" + data.hex())
    return data

def magicwrite(sio, addr, msg, verbosity=0):
    """ Perform a magic write

    This function mimics a particular packet pattern seen in the
    preamble and finalizer where a write command is surrounded by two
    magic frames. Timing of these packets is special and sending these
    too close together causes a hang.  The 70ms is from original
    captures.
    """

    precontent = bytes([0x05, 0x00, 0x00, 0x00, 0x00])
    sio.write(magicFrame(precontent))
    if verbosity: eprint(">" + magicFrame(precontent).hex())
    sio.flush()
    time.sleep(0.07)
    sio.write(writeFrame(addr, msg))
    if verbosity: eprint(">" + writeFrame(addr, msg).hex())
    sio.flush()
    time.sleep(0.07)
    data = waitonread(sio)
    postcontent = bytes([0x05, 0x00, 0x00, 0x00, 0xa5])
    sio.write(magicFrame(postcontent))
    if verbosity: eprint(">" + magicFrame(postcontent).hex())
    sio.flush()
    time.sleep(0.07)

def magiccommand(sio, msg, verbosity=0):
    """ Perform a magic command

    There are times where the CPS sends a magic frame by itself and
    this reproduces that behavior.  Magic frames never have a received
    frame.
    """
    sio.write(magicFrame(msg))
    if verbosity: eprint(">" + magicFrame(msg).hex())
    sio.flush()
    time.sleep(0.065)

def readmem(sio, addr, verbosity=0, retries=25):
    """ Perform a simple read

    This is a simple memory reading routine.  A read frame is sent and
    the received frame is decoded and matched to its sequence number
    with the value returned.
    """
    readOk = False
    retval = b''
    while not readOk:
        frame = readFrame(addr)
        if verbosity: eprint(">" + frame.hex())
        sio.write(frame)
        sio.flush()
        size = sio.in_waiting
        i = retries
        while size == 0 and i > 0:
            time.sleep(0.001)
            size = sio.in_waiting
            i -= 1
        if retries == 0:
            if verbosity: eprint('no data')
            continue
        data = sio.read(size)
        if verbosity: eprint(">" + data.hex())
        inboundFrame = Frame(data)
        readOk = inboundFrame.seq == 1 and not inboundFrame.check_fail
        retval = inboundFrame.content
    return retval

class Frame:
    """ Received Frame class

    This class decodes possible received Frames.
    """
    ack = False
    check_fail = False
    seq = 0
    length = 0
    content = bytes([])
    def __init__(self, msg):
        msg = unescaper(msg)
        if len(msg) <= 4:
            if(msg == b'\x11\x13'):
                self.ack = True
            else:
                # impossibly short frame something is wrong.
                self.check_fail = True
            return
        if (msg[-1] != compute_check(msg[3:-1])):
            self.check_fail = True
            return
        self.seq = msg[4]
        self.length = msg[2]
        self.content = msg[5:-1]
    def __repr__(self):
        return 'packet length {} seq {} content {} ack {} check {}'.format(self.length, self.seq, self.content, self.ack, self.check_fail)


def knock(sio, verbosity=0, retries=25):
    """ Replays the initial knock sequence

    This sequence and timing is from the CPS software capture.
    """
    knock_worked = False
    while not knock_worked and retries > 0:
        sio.write(knockFrame())
        if verbosity: eprint(">" + knockFrame().hex())
        sio.flush()
        time.sleep(0.001)
        data = waitonread(sio)
        if verbosity: eprint("<" + data.hex())
        response = Frame(data)
        if response.seq == 1 and response.content == b'\x80':
            knock_worked = True
        else:
            if verbosity: eprint('no data')
            time.sleep(0.25)
        retries -= 1
    return knock_worked

def burstRead(sio, begin, end, verbosity=0, burst=16):
    """ Burst several read commands and then parse them back out.

    Several frames are sent without waiting for all of the replies to come back and then parsed in a bundle
    """
    addr = begin
    offset = 1
    sio.reset_input_buffer()
    while addr < end:
        readbuffer = b''
        while offset < burst:
            frame = readFrame(addr, offset)
            sio.write(readFrame(addr, offset))
            addr = addr + 4
            offset = offset + 1
            size = sio.in_waiting
            if size > 0:
                readbuffer += sio.read(size)
        sio.flush()
        time.sleep(0.001)
        size = sio.in_waiting
        if size > 0:
            readbuffer += sio.read(size)
        sys.stdout.buffer.write(bufferParser(readbuffer, burst))
        offset = 1
    return 0

def bufferParser(readbuffer, burst=16):
    """ Parse concatenated frames from a burst


    """
    out = b''
    offset = 1
    while len(readbuffer) > 0:
        length = readbuffer[2]
        if readbuffer[4] == offset:
            out += readbuffer[5:3+length]
            offset += 1
        readbuffer = readbuffer[4+length:]
    return out



def preamble(sio, verbosity=0 ):
    """ Replay the preamble

    """
    knock_worked = knock(sio, verbosity)
    if not knock_worked:
        eprint("Serial communication failed")
        return

    # Begin the preamble
    for x in range(0, 25):
        content = bytes([0x03, 0x00, 0x00, 0x00, 0x80])
        magiccommand(sio, content, verbosity)
    # find the magic address for the following writes
    magicaddr = fetchWord(sio, 0x81c00270, verbosity)
    time.sleep(1.24)

    for x in range(0,25):
        magicwrite(sio, magicaddr, bytes([0xaa, 0x06, 0x0a, 0x06, 0x0a, 0xbb, 0x00, 0x00]), verbosity)

    # without these, the header isn't there
    # clears the destination area
    magicwrite(sio, magicaddr, bytes([0xaa, 0x07, 0x00, 0x2b, 0x00, 0x2c, 0xbb, 0x00, 0x00, 0x00]), verbosity)
    # purpose of this is unknown
    magicwrite(sio, magicaddr, bytes([0xaa, 0x06, 0x0a, 0x07, 0x0b, 0xbb, 0x00, 0x00]), verbosity)
    # causes the red led to blink
    magicwrite(sio, magicaddr, bytes([0xaa, 0x06, 0x0a, 0x03, 0x0f, 0xbb, 0x00, 0x00]), verbosity)
    # causes something to populate this header area
    magicwrite(sio, magicaddr, bytes([0xaa, 0x06, 0x0a, 0x00, 0x0c, 0xbb, 0x00, 0x00]), verbosity)

def fetchWord(sio, addr, verbosity=0):
    pointer = readmem(sio, addr, verbosity)
    return int.from_bytes(pointer, 'little')

def readCodeplug(sio, verbosity=0 ):
    # Make a note of the last time we sent a magic command
    last_magic_write = time.time()
    magicaddr = fetchWord(sio, 0x81c00270, verbosity)

    # fetch codeplug location
    cpsPointerPointer = fetchWord(sio, 0x81c00268, verbosity)
    cpsHeaderPointer = fetchWord(sio, cpsPointerPointer, verbosity)
    cpsHeaderLength = fetchWord(sio, cpsPointerPointer + 4, verbosity)
    cpsDataPointer = fetchWord(sio, cpsPointerPointer + 8, verbosity)
    cpsDataLength = fetchWord(sio, cpsHeaderPointer + 0x14, verbosity) - cpsHeaderLength

    readMemRange(sio, cpsHeaderPointer, cpsHeaderPointer+cpsHeaderLength, verbosity)
    readMemRange(sio, cpsDataPointer, cpsDataPointer+cpsDataLength, verbosity)

def readMemRange(sio, begin, end, verbosity=0 ):
    """ Read a memory range

    """
    # Make a note of the last time we sent a magic command
    last_magic_write = time.time()
    magicaddr = fetchWord(sio, 0x81c00270, verbosity)

    addr = begin
    while addr < end:
        data = readmem(sio, addr, verbosity)
        if len(data) == 4:
            sys.stdout.buffer.write(data)
            addr = addr + 4
        cur_time = time.time()
        if (cur_time - last_magic_write - 5) > 0:
            magicwrite(sio, magicaddr, bytes([0xaa, 0x06, 0x0a, 0x00, 0x0c, 0xbb, 0x00, 0x00]), verbosity)
            last_magic_write = cur_time

def finalize(sio, verbosity=0 ):
    """ The Read finalize command

    """
    magicaddr = fetchWord(sio, 0x81c00270, verbosity)
    magicwrite(sio, magicaddr, bytes([0xaa, 0x06, 0x0a, 0x04, 0x08, 0xbb, 0x00, 0x00]), verbosity)
    magicwrite(sio, magicaddr, bytes([0xaa, 0x06, 0x0a, 0x07, 0x0b, 0xbb, 0x00, 0x00]), verbosity)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Auctus A6 dumper')
    parser.add_argument('--begin', type=lambda x: int(x,0),
                        help='begin address default 0x82000000',
                        default=0x82000000)
    parser.add_argument('--end', type=lambda x: int(x,0),
                        help='end address default 0x8200ff00',
                        default=0x8200ff00)
    parser.add_argument('-p', '--port', default='/dev/ttyUSB0',
                        type=str, help='serial port')
    parser.add_argument('-b','--baudrate', default=921600,
                        type=int, help='baud rate')
    parser.add_argument('-c','--codeplug', action='store_true',
                        help='Read the codeplug only')
    parser.add_argument('-v','--verbosity', default=0, action='count',
                        help='print sent and received frames to stderr for debugging')
    parser.add_argument('-V', '--version', action='version',
                        version='%(prog)s 0.0.1',
                        help='display version information and exit')
    args = parser.parse_args()
    sio = serial.Serial(args.port, args.baudrate, serial.EIGHTBITS, serial.PARITY_NONE, serial.STOPBITS_ONE, xonxoff=True, rtscts=False, timeout = 0.001)
    sio.flush()
    preamble(sio, args.verbosity)
    if args.codeplug:
        readCodeplug(sio, args.verbosity)
    else:
        readMemRange(sio, args.begin, args.end, args.verbosity)
    finalize(sio, args.verbosity)
    sio.close()
