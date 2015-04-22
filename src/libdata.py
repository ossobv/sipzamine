# vim: set ts=8 sw=4 sts=4 et ai tw=79:
# sipzamine Data source lib
# Copyright (C) 2011-2015 Walter Doekes, OSSO B.V.

import datetime
import re
import socket
import struct
import sys
try:
    import pcap  # python-libpcap
except ImportError:
    # Fine.. but you must use the VerboseTcpdumpReader, feeding the output of
    # ``tcpdump -nnvs0`` to stdin.
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

    def __init__(self, filenames, pcap_filter=None, min_date=None,
                 max_date=None):
        if not pcap:
            raise ImportError('PcapReader requires pylibpcap support '
                              '(python-libpcap)')

        self.filenames = filenames
        self.pcap_filter = pcap_filter

        # This way we'll only need to watch out for a single exception when
        # iterating.
        class BogoPcap():
            def next(self):
                raise TypeError("'NoneType' object is not iterable")
        self.pcap = BogoPcap()

        self.min_date = min_date
        self.max_date = max_date

        self.filename = None
        self.link_type = None

        self.warnings = set()  # store what we've have warned about

    def __iter__(self):
        return self

    def next(self):
        while True:
            while True:
                # Re-open a new file until we have a packet
                try:
                    # Fetch the next entry or raise TypeError:
                    # "'NoneType' object is not iterable"
                    (pktlen, data, timestamp) = self.pcap.next()
                except TypeError:
                    # Unfortunately, the python-libpcap library does not
                    # close any fd's. Looks like pcap_close() is never
                    # called (and calling _pcap.delete_pcapObject(...)
                    # ourselves does not help).
                    # This means that we have to rely on the OS for FD
                    # cleanup when finishing :(
                    self.pcap = None

                    # Are we done?
                    if not self.filenames:
                        raise StopIteration()

                    # Do we need a new file?
                    self.pcap = pcap.pcapObject()
                    self.filename = self.filenames.pop(0)
                    self.pcap.open_offline(self.filename)
                    if self.pcap_filter:
                        self.pcap.setfilter(self.pcap_filter, 0, 0)
                    # set link type, needed below
                    self.link_type = self.pcap.datalink()
                else:
                    break

            if self.min_date and self.min_date > timestamp:
                continue
            if self.max_date and self.max_date < timestamp:
                continue

            # Get frame payload (pcap-linktype(7))
            # http://www.tcpdump.org/linktypes.html
            if self.link_type == pcap.DLT_RAW:  # Don't know??
                payload = data
            elif self.link_type == pcap.DLT_EN10MB:  # 0x1 Ethernet
                # to_mac = data[0:6]
                # from_mac = data[6:12]
                payload = data[12:]
            elif self.link_type == pcap.DLT_LINUX_SLL:  # 0x71 Linux Cooked SSL
                # packet_type = data[0:2]
                # arphdr_type = data[2:4]
                # lladdr_len = data[4:6] # =6 for mac
                # lladdr = data[6:14] # first 6 bytes for macaddr
                payload = data[14:]
            else:
                raise NotImplementedError(
                    'Not implemented link type %d (0x%x) in %s' %
                    (self.link_type, self.link_type, self.filename))

            # Get ethernet data
            # http://en.wikipedia.org/wiki/EtherType
            data = None
            while True:
                if self.link_type == pcap.DLT_RAW:
                    data = payload
                    break
                elif payload[0:2] == '\x08\x00':    # IPv4
                    data = payload[2:]
                    break
                elif payload[0:2] == '\x81\x00':    # 802.1Q
                    # tci = payload[2:2]  # pcp+cfi+vid
                    payload = payload[4:]
                    continue
                elif payload[0:2] == '\x88\xa8':    # 802.1ad (Q-in-Q)
                    raise NotImplementedError('VLAN-tagged ethernet frame '
                                              'decoding not implemented yet.')
                elif payload[0:2] == '\x91\x00':    # 802.1QinQ (non-standard)
                    raise NotImplementedError('VLAN-tagged ethernet frame '
                                              'decoding not implemented yet.')
                elif payload[0:2] == '\x86\xdd':    # IPv6
                    break  # ignore
                else:                               # Other stuff (like ARP)
                    break  # ignore
            # No relevant data? Continue to next packet
            if data is None:
                continue

            version = ord(data[0]) >> 4
            header_len = (ord(data[0]) & 0x0f) << 2
            if version != 4:
                raise ValueError('How did you get a version %d in an IPv4 '
                                 'header?' % (version,))

            flags = ord(data[6]) >> 5
            fragment_offset = struct.unpack('>H', data[6:8])[0] & 0x1fff
            if flags & 2:
                msg = ('(packet defragmentation on t %f not implemented yet, '
                       'suppressing warning)')
                self.warn_once('more_fragments', msg % (timestamp,))
                # but, carry on
            if fragment_offset:
                msg = '(skipping IP fragment on t %f, suppressing warning)'
                self.warn_once('fragment', msg % (timestamp,))
                continue

            try:
                proto_num = ord(data[9])
                ip_proto = self.protocols[proto_num]
            except KeyError:
                msg = ('(skipping unknown IP protocol %d on t %f, suppressing '
                       'warning)' % (proto_num, timestamp))
                self.warn_once('proto:%d' % (proto_num,), msg)
                continue

            from_ = pcap.ntoa(struct.unpack('i', data[12:16])[0])
            to = pcap.ntoa(struct.unpack('i', data[16:20])[0])

            # IP => TCP/UDP/ICMP/fragment
            data = data[header_len:]

            if ip_proto in ('TCP', 'UDP'):
                from_ = (from_, struct.unpack('>H', data[0:2])[0])  # add port
                to = (to, struct.unpack('>H', data[2:4])[0])        # add port

                if ip_proto == 'TCP':
                    # FIXME: we need another layer for reassembling TCP
                    # into a stream before attempting to do app-protocol
                    # decoding on it.
                    data_offset = (ord(data[12]) >> 4) * 4
                    data = data[data_offset:]

                else:
                    data = data[8:]

            elif ip_proto == 'ICMP':
                # Parsing ICMP is nice if we want to trace port-
                # unreachable messages.
                msg = ('(skipping IP ICMP protocol on t %f, not yet '
                       'implemented, suppressing warning)')
                self.warn_once('proto:icmp', msg % (timestamp,))
                continue
            else:
                raise NotImplementedError(ip_proto)

            datetime_ = datetime.datetime.fromtimestamp(timestamp)
            return IpPacket.create(datetime_, ip_proto, from_, to, data)

    def warn_once(self, key, message):
        if key not in self.warnings:
            print >>sys.stderr, message
            self.warnings.add(key)


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
        # The tcpdump verbose output does not show dates.
        # FIXME: it does show the date if you supply -tttt, but until we
        # specify that, we need a bogus date.
        self.bogus_date = bogus_date or datetime.date.today()
        self.last_datetime = None

        # FIXME: add warning if you're using date filter but no bogus_date
        self.min_date = min_date
        self.max_date = max_date
        if min_date or max_date:
            raise NotImplementedError('Filtering by date is not implemented '
                                      'for the tcpdump input.')

    def __iter__(self):
        self.line = self.input.next()
        return self

    def next(self):
        if not self.input:
            raise StopIteration()

        skip_it = True
        while skip_it:
            m = self.time_re.match(self.line)
            assert m, 'Failed to match time_re: %r' % (self.line,)
            time = m.groups()[0]

            # Parse time
            parsed = time.split(':', 2)
            parsed2 = parsed[2].split('.')
            time = datetime.datetime(
                self.bogus_date.year, self.bogus_date.month,
                self.bogus_date.day,
                int(parsed[0]), int(parsed[1]),
                int(parsed2[0]), int(parsed2[1])
            )
            if self.last_datetime and time < self.last_datetime:
                time += datetime.timedelta(days=1)
                self.bogus_date += datetime.timedelta(days=1)
            self.last_datetime = time

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
    tcpdata = '''08:36:13.396439 IP (tos 0x0, ttl 64, id 3380, offset 0, \
flags [DF], proto TCP (6), length 123)
    192.168.1.69.43620 > 192.168.1.70.1194: Flags [P.], cksum 0xdaa7 \
(correct), seq 4089035108:4089035179, ack 3621271904, win 15340, options \
[nop,nop,TS val 1337847 ecr 459981631], length 71
08:36:13.435130 IP (tos 0x0, ttl 55, id 48663, offset 0, flags [DF], proto \
TCP (6), length 52)
    192.168.1.70.1194 > 192.168.1.69.43620: Flags [.], cksum 0xbba0 \
(correct), ack 71, win 717, options [nop,nop,TS val 459982456 ecr 1337847], \
length 0
'''
    regdata = '''22:24:58.461807 IP (tos 0x68, ttl 55, id 0, offset 0, \
flags [DF], proto UDP (17), length 712)
    11.22.33.44.5566 > 22.22.22.22.5060: SIP, length: 684
\tREGISTER sip:sip.example.com SIP/2.0
\tVia: SIP/2.0/UDP 11.22.33.44:5566;branch=z9hG4bK-53a7e057
\tFrom: "Someone" <sip:account@sip.example.com>;tag=6f3670031b444da1o0
\tTo: "Someone" <sip:account@sip.example.com>
\tCall-ID: d5122bf8-525c393a@192.168.1.1
\tCSeq: 131052 REGISTER
\tMax-Forwards: 70
\tAuthorization: Digest username="account",realm="example.com",\
nonce="47abd040",uri="sip:sip.example.com",algorithm=MD5,\
response="397a10af3e14baf63cfa22d755dce50b"
\tContact: "Someone" <sip:account@11.22.33.44:5566>;expires=60
\tUser-Agent: Cisco/SPA525G-7.4.9a
\tContent-Length: 0
\tAllow: ACK, BYE, CANCEL, INFO, INVITE, NOTIFY, OPTIONS, REFER, UPDATE
\tSupported: replaces
\t
\t
'''
    byedata = '''22:37:08.388039 IP (tos 0x10, ttl 62, id 0, offset 0, \
flags [DF], proto UDP (17), length 628)
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
    reader = VerboseTcpdumpReader(StringIO(tcpdata + regdata + regdata +
                                           byedata))
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
    # test_pcapreader()
    # test_verbosetcpdumpreader()
    p = PcapReader([sys.argv[1]])
    for i in p:
        print '%s: %s >> %s' % (i.datetime, i.from_, i.to)
        print repr(i.data)
