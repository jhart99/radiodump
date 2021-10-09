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




class CoolProtocol(asyncio.Protocol):

    def __init__(self):
        """ Constructor
        start and end are the memory range desired
        Future is the future object signaling the thread has completed.

        """
        super().__init__()

    def connection_made(self, transport):
        """Store the serial transport and schedule the task to send data.
        """
        # eprint('CoolProtocol connection created')
        self.transport = transport
        self.transport.set_write_buffer_limits(128, 16)
        self.buf = bytes()
        self.messages = []

    def connection_lost(self, exc):
        """Connection closed
        Needed to set the future flag showing this thread is complete
        """
        # eprint('CoolProtocol connection lost')
        super().connection_lost(exc)

    def data_received(self, data):
        """Store received data and process buffer to look for frames

        if the current read block is finished. Set the complete
        semaphore if appropriate
        """
        # eprint(data.hex())
        self.buf += data
        self.buf = self.unescaper(self.buf)
        # eprint(self.buf.hex())
        self.process_buffer()

    def process_buffer(self):
        """ Process in the read buffer

        scans for ad begin words and discards defective packets automatically
        """
        if len(self.buf) > 1024:
            self.buf = bytes()
        begin = self.buf.find(0xad)
        while (begin >= 0):
            if len(self.buf) < begin + 3:
                # too short to read msg length, fragmented
                return
            msglen = int.from_bytes(self.buf[begin+1:begin+3], byteorder = 'big', signed = False)
            nextframe = begin + 4 + msglen
            if len(self.buf) < nextframe - 1:
                # frame incomplete, fragmented
                return
            frame = self.buf[begin:nextframe]
            # eprint(self.buf[begin:nextframe].hex())
            msg = frame[3:-1]
            if self.compute_check(msg) == frame[-1]:
                # only process the message if the check field matches
                self.message_handler(msg)
            self.buf = self.buf[nextframe:]
            begin = self.buf.find(0xad)

    def message_handler(self, message):
        # eprint('CoolProtocol Message Handler')
        self.messages.append(msg)

    def escaper(self, msg):
        """ escape message

        this function escapes special characters in the message.  These
        are 0x5c, 0x11 and 0x13 which are '\' and XON and XOFF characters.

        """

        out = bytes(sum([[0x5c, 0x5c ^ x ^ 0xa3] if x in [0x11, 0x13, 0x5c] else [x] for x in msg], []))
        return out

    def unescaper(self, msg):
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

    def compute_check(self, msg):
        """ Compute the check value for a message

        AUCTUS messages use a check byte which is simply the XOR of all
        the values of the message.

        """

        if len(msg) == 0:
            return 0
        return functools.reduce(operator.xor, msg)

    def format_frame(self, message):
        """ Format a raw message into a frame

        AUCTUS frames are of the form AD 00 XX FF ...message... YY
        where XX is the length of the message and YY is the check byte
        Additionally certain bytes in the message are escaped.

        """

        header = bytes([0xad, 0x00])
        begin = bytes([0xff])
        msg = begin + message
        msglen = bytes([len(msg)])
        check = bytes([self.compute_check(msg)])
        return self.escaper(header + msglen + msg + check)

    def read_frame(self, addr, seq = 1):
        """ make a frame to read a word at a memory address

        this function creates a frame to read the memory from the device
        suitable for serial transmission.

        """

        command = 0x02
        msg = struct.pack('<BIB', command, addr, seq)
        return self.format_frame(msg)

    def magic_frame(self, content):
        """ make a frame containing magic(an unknown command)

        this function creates a frame to do some device magic and these
        frames are used in the preamble and finalizer commands.

        """

        command = bytes([0x84])
        msg = command + content
        return format_frame(msg)

    def write_frame(self, addr, content):
        """ make a frame containing a write command

        this function creates a frame to do write a multiple byte content
        at a specific memory address.  The length need not be a word, but
        could be 16 bytes or more.

        """

        command = bytes([0x83])
        addr = struct.pack('<I', addr)
        msg = command + addr + content
        return format_frame(msg)

    def knock_frame(self):
        """ make a frame containing a knock command

        this function creates a frame that I assume wakes up the device
        for further commands.

        """

        command = bytes([0x04])
        content = bytes([0x03, 0x00, 0x00, 0x00, 0x01])
        msg = command + content
        return format_frame(msg)

class MemoryReader(CoolProtocol):

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
        # eprint('MemoryReader connection created')
        super().connection_made(transport)
        self.burstLen = 0x40
        self.received = [False]*self.burstLen
        self.outputbuf = bytearray(4*self.burstLen)
        self.complete = False
        asyncio.get_running_loop().create_task(self.readmem(self.start, self.end))
        # eprint('MemoryReader.send() scheduled')

    def connection_lost(self, exc):
        """Connection closed
        Needed to set the future flag showing this thread is complete
        """
        # eprint('MemoryReader closed')
        if not self.f.done():
            self.f.set_result(b''.join(self.memoryData))
        super().connection_lost(exc)


    def message_handler(self, message):
        # eprint(message.hex())
        if len(message) != 6:
            return
        seq = message[1] - 1 - self.offset
        if seq < 0:
            return
        if seq >= self.burstLen:
            return
        self.received[seq] = True # offset by 1 for zero index
        self.outputbuf[4*seq:4*seq+4] = message[2:]
        self.complete = self.burstLen == sum(self.received)

    async def readmem(self, start, stop):
        """ Read a range of memory locations from start to stop
        """
        burstBegin = start
        self.offset = 0x0
        while burstBegin < stop:
            # because of issues with late packets coming back from the radio, we switch between two different subsets of values for sequences.
            if stop - burstBegin < 4*0x40:
                # need an integer divide by 4 to find the number of words left
                self.burstLen = (stop - burstBegin) >> 2
            else:
                self.burstLen = 0x40

            seq = 1
            toot = 0
            self.received = [False]*self.burstLen
            self.outputbuf = bytearray(4 * self.burstLen)
            burstStop = burstBegin + (4 * self.burstLen)
            self.complete = False
            while not self.complete:
                for seq, read in enumerate(self.received):
                    if self.complete:
                        break
                    if not read:
                        cur = burstBegin + 4 * seq
                        message = self.read_frame(cur, seq + 1 + self.offset)
                        self.transport.serial.write(message)
                        # eprint(f'MemoryReader sent: {message.hex()}')
                        if toot % 16 == 0:
                           await asyncio.sleep(0.0001)
                        toot += 1
                await asyncio.sleep(0.001)
            eprint('block complete {}'.format(hex(burstBegin)))
            self.memoryData.append(self.outputbuf)
            burstBegin += 4*self.burstLen
            # This pause here is to make sure that all messages from
            # the current block arrive after we are complete
            await asyncio.sleep(0.001)
            # alternate the offset so we can reject old packets
            if self.offset == 0x0:
                self.offset = 0x40
            else:
                self.offset = 0x0
        if not self.f.done():
            self.f.set_result(b''.join(self.memoryData))
        # self.transport.close()

class CPSReader(MemoryReader):

    def __init__(self, future):
        """ Constructor
        start and end are the memory range desired
        Future is the future object signaling the thread has completed.

        """
        self.CPSData = []
        self.f = future
        self.knock_worked = False

    def connection_made(self, transport):
        """Store the serial transport and schedule the task to send data.
        """
        eprint('CPSReader connection created')
        self.burstLen = 0x80
        self.received = [False]*self.burstLen
        self.outputbuf = bytearray(4*self.burstLen)
        self.complete = False
        self.loop = asyncio.get_running_loop()
        self.loop.create_task(self.preamble())
        eprint('CPRReader.preamble() scheduled')

    def connection_lost(self, exc):
        """Connection closed
        Needed to set the future flag showing this thread is complete
        """
        # eprint('MemoryReader closed')
        if not self.f.done():
            self.f.set_result(b''.join(self.memoryData))
        super().connection_lost(exc)

    async def preamble(self):
        while not self.knock_worked:
            self.transport.write(self.knock_frame())
            await asyncio.sleep(0.001)
        eprint("knock worked")


    def message_handler(self, message):
        # eprint(message.hex())
        if len(message) == 3:
            self.knock_worked = True
        if len(message) != 6:
            return
        seq = message[1] - 1
        if seq >= 0 and not self.complete:
            # if less than zero, it is an event
            if seq < self.burstLen:
                    self.received[seq] = True # offset by 1 for zero index
                    self.outputbuf[4*seq:4*seq+4] = message[2:]
        self.complete = self.burstLen == sum(self.received)


async def main(args):
    loop = asyncio.get_running_loop()
    readMemory = loop.create_future()
    readMemory2 = loop.create_future()
    cps = loop.create_future()

    cps_factory = functools.partial(
        CPSReader,
        future = cps)

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


    # cpscoro = serial_asyncio.connection_for_serial(loop, cps_factory, serial_port)
    #eprint('preamble scheduled')
    #cpsTask = loop.create_task(cpscoro)
    #await cps

    #writer = serial_asyncio.connection_for_serial(loop, writer_factory, serial_port)
    #eprint('MemoryReader scheduled')
    #writerTask = loop.create_task(writer)
    #await readMemory
    #writerTask.cancel()
    writer2 = serial_asyncio.connection_for_serial(loop, writer_factory2, serial_port)
    writer2Task = loop.create_task(writer2)
    await readMemory2
    writer2Task.cancel()
    output = open(args.out, "wb")
    output.write(readMemory2.result())
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
