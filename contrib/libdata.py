# vim: set ts=8 sw=4 sts=4 et ai:
import datetime, re
try:
    import pcap # python-libpcap
except ImportError:
    # Fine.. but you must use the VerboseTcpdumpReader, passing tcpdump -nnvls0 output.
    pcap = None

from libproto import IpPacket


class VerboseTcpdumpReader(object):
    '''
    Reads formatted verbose tcpdump output (-nnvls0).
    '''
    def __init__(self, file, date=None):
        self.input = file
        self.line = None

        self.time_re = re.compile('^(\d{2}:\d{2}:\d{2}\.(\d+)).*$')
        self.from_to_re = re.compile('^    ([0-9.]+) > ([0-9.]+).*$')
        self.date = date or datetime.date.today() # you can supply a different date if you want, the verbose output doesn't show any
        # FIXME increase the date when time wraps in next() iterator!

    def __iter__(self):
        return self

    def next(self):
        if not self.input:
            raise StopIteration
        if not self.line:
            self.line = self.input.next()

        m = self.time_re.match(self.line)
        time = m.groups()[0]

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
            #self.input.close()
            self.input = None

        # last line should contain TAB only, but sometimes it doesn't
        if data and data[-1] == '\n':
            data.pop()

        # Parse time
        parsed = time.split(':', 2)
        parsed2 = parsed[2].split('.')
        time = datetime.datetime(self.date.year, self.date.month, self.date.day, int(parsed[0]), int(parsed[1]), int(parsed2[0]), int(parsed2[1]))
        # Parse from_/to
        from_ = tuple(from_.rsplit('.', 1))
        to = tuple(to.rsplit('.', 1))
        # Select protocol
        ip_proto = 'UDP' # tcodump verbose mode lists TCP data completely differently
        # (CRs are removed by tcpdump -v, data is now LF separated)
        return IpPacket.create(time, ip_proto, from_, to, ''.join(data))



class PcapReader(object):
    '''
    Reads a pcap file.
    '''
    def __init__(self, file):
        raise NotImplementedError()


def test_verbosetcpdumpreader():
    from StringIO import StringIO
    from libprotosip import SipPacket
    data = '''22:24:58.461807 IP (tos 0x68, ttl 55, id 0, offset 0, flags [DF], proto UDP (17), length 712)
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
    reader = VerboseTcpdumpReader(StringIO(data + data))
    for i, packet in enumerate(reader):
        if not isinstance(packet, SipPacket):
            raise RuntimeError('Expected a SipPacket')
    if i != 1:
        raise RuntimeError('Expected exactly two results')


if __name__ == '__main__':
    test_verbosetcpdumpreader()
