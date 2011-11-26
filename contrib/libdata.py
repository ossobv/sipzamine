# vim: set ts=8 sw=4 sts=4 et ai:
# sipcaparseye Data source lib
# Copyright (C) Walter Doekes, OSSO B.V. 2011

import datetime, re, socket, struct, sys
try:
    import pcap # python-libpcap
except ImportError:
    # Fine.. but you must use the VerboseTcpdumpReader, passing tcpdump -nnvs0 output.
    pcap = None

from libproto import IpPacket


class PcapReader(object):
    '''
    Reads a pcap file.
    '''
    protocols = {
        socket.IPPROTO_TCP: 'TCP',
        socket.IPPROTO_UDP: 'UDP',
        socket.IPPROTO_ICMP: 'ICMP'
    }

    def __init__(self, filenames, pcap_filter=None, min_date=None, max_date=None):
        if not pcap:
            raise ImportError('PcapReader requires pylibpcap support (python-libpcap)')

        self.filenames = filenames
        self.pcap_filter = pcap_filter
        self.pcap = pcap.pcapObject()

        self.min_date = min_date
        self.max_date = max_date

        self.proto_warnings = set() # store which protocols we have warned about

    def __iter__(self):
        return self

    def next(self):
        while True:
            while True:
                # Re-open a new file until we have a packet
                try:
                    (pktlen, data, timestamp) = self.pcap.next()
                except (Exception, TypeError):
                    # pcapObject must be initialized via open_* / Nonetype is not iterable
                    if not self.filenames:
                        raise StopIteration
                    filename = self.filenames.pop(0)
                    self.pcap.open_offline(filename)
                    if self.pcap_filter:
                        self.pcap.setfilter(self.pcap_filter, 0, 0)
                else:
                    break

            if self.min_date and timestamp < self.min_date:
                continue
            if self.max_date and timestamp > self.max_date:
                continue

            # Ethernet => IP
            if data[12:14] != '\x08\x00':
                continue
            data = data[14:]

            version = (ord(data[0]) & 0xf0) >> 4
            header_len = ord(data[0]) & 0x0f
            if version != 4:
                # IPv6 is *not* supported ATM
                continue

            try:
                num = ord(data[9])
                ip_proto = self.protocols[num]
            except KeyError:
                if num not in self.proto_warnings:
                    print >>sys.stderr, '(skipping unknown IP protocol %d on t %f)' % (num, timestamp)
                    self.proto_warnings.add(num)
                continue

            from_ = pcap.ntoa(struct.unpack('i', data[12:16])[0])
            to = pcap.ntoa(struct.unpack('i', data[16:20])[0])

            # IP => TCP/UDP/ICMP
            data = data[4 * header_len:]

            if ip_proto in ('TCP', 'UDP'):
                from_ = (from_, struct.unpack('>H', data[0:2])[0])
                to = (to, struct.unpack('>H', data[2:4])[0])

                if ip_proto == 'TCP':
                    data_offset = (ord(data[12]) & 0xf) * 4 + 20
                    data = data[data_offset:]

                else:
                    data = data[8:]

            else:
                if 'ICMP' not in self.proto_warnings:
                    # Parsing ICMP is nice if we want to trace port-
                    # unreachable messages.
                    print >>sys.stderr, '(skipping IP ICMP protocol on t %f, not yet implemented)' % (timestamp,)
                    self.proto_warnings.add('ICMP')
                continue

            datetime_ = datetime.datetime.fromtimestamp(timestamp)
            return IpPacket.create(datetime_, ip_proto, from_, to, data)
        

class VerboseTcpdumpReader(object):
    '''
    Reads formatted verbose tcpdump output (-nnvs0). It will read only
    UDP. Everything else is skipped.
    '''
    def __init__(self, file, bogus_date=None, min_date=None, max_date=None):
        self.input = file
        self.line = None

        self.time_re = re.compile('^(\d{2}:\d{2}:\d{2}\.(\d+)).*$')
        self.from_to_re = re.compile('^    ([0-9.]+) > ([0-9.]+).*$')
        self.bogus_date = bogus_date or datetime.date.today() # you can supply a different date if you want, the verbose output doesn't show any
        # FIXME increase the date when time wraps in next() iterator!

        # FIXME: add warning if youre using date filter but no bogus_date
        self.min_date = min_date
        self.max_date = max_date
        if min_date or max_date:
            raise NotImplementedError() # convert date to datetime and filter those?

    def __iter__(self):
        self.line = self.input.next()
        return self

    def next(self):
        if not self.input:
            raise StopIteration

        skip_it = True
        while skip_it:
            m = self.time_re.match(self.line)
            assert m, 'Failed to match time_re: %r' % (self.line,)
            time = m.groups()[0]
            if 'proto UDP (17)' in self.line:
                skip_it = False

            self.line = self.input.next()
            m = self.from_to_re.match(self.line)
            assert m, 'Failed to match from_to_re: %r' % (self.line,)
            from_ = m.groups()[0]
            to = m.groups()[1]

            # get all until eof or next packet
            data = []
            try:
                while True:
                    self.line = self.input.next()
                    if self.time_re.match(self.line):
                        break
                    elif self.line.startswith('\t'):
                        data.append(self.line[1:])
            except StopIteration:
                self.input = None
                if skip_it:
                    raise

        # Parse time
        parsed = time.split(':', 2)
        parsed2 = parsed[2].split('.')
        time = datetime.datetime(
            self.bogus_date.year, self.bogus_date.month, self.bogus_date.day,
            int(parsed[0]), int(parsed[1]), int(parsed2[0]), int(parsed2[1])
        )

        # Check time against our filters
        # TODO

        # Last line should contain TAB only, but sometimes it doesn't
        if data and data[-1] == '\n':
            data.pop()

        # Parse from_/to
        from_ = from_.rsplit('.', 1)
        from_ = (from_[0], int(from_[1]))
        to = to.rsplit('.', 1)
        to = (to[0], int(to[1]))

        # (CRs are removed by tcpdump -v, data is now LF separated)
        # FIXME: do something about the CRs
        return IpPacket.create(time, 'UDP', from_, to, ''.join(data))


def test_verbosetcpdumpreader():
    from StringIO import StringIO
    from libprotosip import SipPacket
    tcpdata = '''08:36:13.396439 IP (tos 0x0, ttl 64, id 3380, offset 0, flags [DF], proto TCP (6), length 123)
    192.168.1.69.43620 > 192.168.1.70.1194: Flags [P.], cksum 0xdaa7 (correct), seq 4089035108:4089035179, ack 3621271904, win 15340, options [nop,nop,TS val 1337847 ecr 459981631], length 71
08:36:13.435130 IP (tos 0x0, ttl 55, id 48663, offset 0, flags [DF], proto TCP (6), length 52)
    192.168.1.70.1194 > 192.168.1.69.43620: Flags [.], cksum 0xbba0 (correct), ack 71, win 717, options [nop,nop,TS val 459982456 ecr 1337847], length 0
'''
    regdata = '''22:24:58.461807 IP (tos 0x68, ttl 55, id 0, offset 0, flags [DF], proto UDP (17), length 712)
    11.22.33.44.5566 > 22.22.22.22.5060: SIP, length: 684
\tREGISTER sip:sip.example.com SIP/2.0
\tVia: SIP/2.0/UDP 11.22.33.44:5566;branch=z9hG4bK-53a7e057
\tFrom: "Someone" <sip:account@sip.example.com>;tag=6f3670031b444da1o0
\tTo: "Someone" <sip:account@sip.example.com>
\tCall-ID: d5122bf8-525c393a@192.168.1.1
\tCSeq: 131052 REGISTER
\tMax-Forwards: 70
\tAuthorization: Digest username="account",realm="example.com",nonce="47abd040",uri="sip:sip.example.com",algorithm=MD5,response="397a10af3e14baf63cfa22d755dce50b"
\tContact: "Someone" <sip:account@11.22.33.44:5566>;expires=60
\tUser-Agent: Cisco/SPA525G-7.4.9a
\tContent-Length: 0
\tAllow: ACK, BYE, CANCEL, INFO, INVITE, NOTIFY, OPTIONS, REFER, UPDATE
\tSupported: replaces
\t
\t
'''
    byedata = '''22:37:08.388039 IP (tos 0x10, ttl 62, id 0, offset 0, flags [DF], proto UDP (17), length 628)
    33.33.33.33.5060 > 22.22.22.22.5060: SIP, length: 600
\tBYE sip:%2b31612345678@22.22.22.22 SIP/2.0
\tRecord-Route: <sip:44.44.44.44;lr>
\tVia: SIP/2.0/UDP 33.33.33.33;branch=z9hG4bKdc31.4e175d83.0
\tVia: SIP/2.0/UDP 44.44.44.44;branch=z9hG4bKdc31.2dae36b2.0
\tVia: SIP/2.0/UDP 44.44.44.45:5062;branch=z9hG4bKtn45io207oohomslv641.1
\tFrom: <sip:+31612345678@44.44.44.45>;tag=4ECD6615-E26C91F-3E86ED92
\tTo: "+31612345678" <sip:+31297386600@44.44.44.44>;tag=as283cd428
\tCall-ID: 1636439003d8d16a5fd4704864096e74@22.22.22.22
\tCSeq: 1 BYE
\tSupported: timer
\tMax-Forwards: 27
\tReason: Q.850 ;cause=16 ;text="Normal call clearing"
\tContent-Length: 0
\t
\t
'''
   
    # Skip non-UDP input
    reader = VerboseTcpdumpReader(StringIO(tcpdata))
    try:
        iter(reader).next()
    except StopIteration:
        pass
    else:
        raise RuntimeError('Expected StopIteration')

    # Parse exactly 3 packets (reg + reg + bye)
    reader = VerboseTcpdumpReader(StringIO(tcpdata + regdata + regdata + byedata))
    for i, packet in enumerate(reader):
        if not isinstance(packet, SipPacket):
            raise RuntimeError('Expected a SipPacket')
    if i != 2:
        raise RuntimeError('Expected exactly three results')

    # Check that the date increases
    reader = VerboseTcpdumpReader(StringIO(regdata + tcpdata + regdata))
    for i, packet in enumerate(reader):
        if i == 0:
            start_date = packet.datetime.date()
    if (packet.datetime.date() - start_date).days != 1:
        raise RuntimeError('Expected date to increase by exactly one day')


if __name__ == '__main__':
    #test_pcapreader()
    test_verbosetcpdumpreader()
