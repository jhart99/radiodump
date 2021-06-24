import asyncio
import serial
import serial_asyncio
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

class MemoryReader(asyncio.Protocol):

    def __init__(self, start, end, future):
        """ Constructor
        start and end are the memory range desired
        Future is the future object signaling the thread has completed.

        """
        super().__init__()
        self.start = start
        self.end = end
        self.f = future
        self.memoryData = []

    def connection_made(self, transport):
        """Store the serial transport and schedule the task to send data.
        """
        #eprint('MemoryReader connection created')
        self.burstLen = 0x80
        self.received = [False]*self.burstLen
        self.outputbuf = bytearray(4*self.burstLen)
        self.complete = False
        self.transport = transport
        self.transport.set_write_buffer_limits(128, 16)
        self.buf = bytes()
        self.msgs_recvd = 0
        asyncio.get_running_loop().create_task(self.readmem(self.start, self.end))
        eprint('MemoryReader.send() scheduled')

    def connection_lost(self, exc):
        """Connection closed
        Needed to set the future flag showing this thread is complete
        """
        eprint('MemoryReader closed')
        eprint('Reader closed')
        if not self.f.done():
            self.f.set_result(b''.join(self.memoryData))
        super().connection_lost(exc)

    def data_received(self, data):
        """Store received data and process buffer to look for frames

        if the current read block is finished. Set the complete
        semaphore if appropriate
        """
        self.buf += data
        self.process_buffer()
        self.complete = sum(self.received) == len(self.received)

    def process_buffer(self):
        """ Process in the read buffer

        scans for ad begin words and discards defective packets automatically
        """
        self.buf = unescaper(self.buf)
        begin = self.buf.find(0xad)
        while (begin >= 0):
            if len(self.buf) < begin + 3:
                # too short frame, fragmented
                return
            msglen = int.from_bytes(self.buf[begin+1:begin+3], byteorder = 'big', signed = False)
            endframe = begin + 4 + msglen
            if len(self.buf) < endframe:
                # frame incomplete, fragmented
                return
            # eprint(self.buf[begin:endframe].hex())
            seq = self.buf[begin+4] - 1
            if seq >= 0:
                # if we have a negative seq it is an event and NOT a read
                msg = self.buf[begin+3:begin+9]
                if seq < self.burstLen and compute_check(msg) == self.buf[begin+9]:
                    self.received[seq] = True # offset by 1 for zero index
                    self.outputbuf[4*seq:4*seq+4] = self.buf[begin+5:begin+9]
            self.buf = self.buf[endframe:]
            begin = self.buf.find(0xad)

    async def readmem(self, start, stop):
        """ Read a range of memory locations from start to stop
        """
        burstBegin = start
        while burstBegin < stop:
            if stop - burstBegin < 4*0x80:
                # need an integer divide by 4 to find the number of words left
                self.burstLen = (stop - burstBegin) >> 2
            else:
                self.burstLen = 0x80

            seq = 1
            toot = 0
            self.received = [False]*self.burstLen
            self.outputbuf = bytearray(4 * self.burstLen)
            burstStop = burstBegin + (4 * self.burstLen)
            self.complete = False
            while not self.complete:
                for seq, read in enumerate(self.received):
                    if not read:
                        cur = burstBegin + 4 * seq
                        message = readFrame(cur, seq + 1)
                        self.transport.serial.write(message)
                        #eprint(f'MemoryReader sent: {message.hex()}')
                        if toot % 16 == 0:
                            await asyncio.sleep(0.001)
                        toot += 1
            await asyncio.sleep(0.001)
            eprint('block complete {}'.format(hex(burstBegin)))
            # sys.stdout.buffer.write(self.outputbuf)
            # sys.stdout.flush()
            self.memoryData.append(self.outputbuf)
            burstBegin += 4*self.burstLen
            await asyncio.sleep(0.001)
        if not self.f.done():
            self.f.set_result(b''.join(self.memoryData))
        # self.transport.close()


async def main(args):
    loop = asyncio.get_running_loop()
    readMemory = loop.create_future()
    readMemory2 = loop.create_future()

    writer_factory = functools.partial(
        MemoryReader,
        start = 0x82000000,
        end = 0x82001000,
        future = readMemory)

    writer_factory2 = functools.partial(
        MemoryReader,
        start = args.begin,
        end = args.end,
        future = readMemory2)

    serial_port = serial.serial_for_url( args.port, args.baudrate,
                                                     serial.EIGHTBITS,
                                                     serial.PARITY_NONE,
                                                     serial.STOPBITS_ONE,
                                                     xonxoff=True,
                                                     rtscts=False,
                                                     timeout = 0.001)


    writer = serial_asyncio.connection_for_serial(loop, writer_factory, serial_port)
    #eprint('MemoryReader scheduled')
    writerTask = loop.create_task(writer)
    await readMemory
    writerTask.cancel()
    writer2 = serial_asyncio.connection_for_serial(loop, writer_factory2, serial_port)
    writer2Task = loop.create_task(writer2)
    await readMemory2
    writer2Task.cancel()
    output = open(args.out, "wb")
    output.write(readMemory.result())
    output.flush()
    output.close()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Auctus A6 dumper')
    parser.add_argument('--begin', type=lambda x: int(x,0),
                        help='begin address default 0x82000000',
                        default=0x82000000)
    parser.add_argument('--end', type=lambda x: int(x,0),
                        help='end address default 0x8200ff00',
                        default=0x8200ff00)
    parser.add_argument('-o', '--out', default='/dev/stdout',
                        type=str, help='output data to')
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
    asyncio.run(main(args))
