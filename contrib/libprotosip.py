# vim: set ts=8 sw=4 sts=4 et ai:
# sipzamin SIP Protocol lib
# Copyright (C) Walter Doekes, OSSO B.V. 2011
from libproto import IpPacket


class SipPacket(IpPacket):
    @classmethod
    def type_probability(cls, packet):
        # TODO: up the probability if one of more of the ports are 5060
        if packet.data:
            word = packet.data.split(' ', 1)[0]
            if word in ('INVITE', 'ACK', 'BYE', 'CANCEL', 'NOTIFY', 'OPTIONS', 'REFER', 'REGISTER',
                    'SUBSCRIBE', 'UPDATE', 'SIP/2.0'): # XXX: not exhaustive..
                return 0.8
        return 0.0

    # Aliases: f:From, t:To, v:Via, s:Subject, l:Content-Length
    def __init__(self, datetime, ip_proto, from_, to, data):
        super(SipPacket, self).__init__(datetime, ip_proto, from_, to, data)
        # FIXME: split up data in header and data
        self.headers = data.split('\n')

    @property
    def method(self):
        if not hasattr(self, '_method'):
            word = self.headers[0].split(' ', 1)[0]
            if word != 'SIP/2.0':
                self._method = word
            else:
                self._method = self.cseq[1]
        return self._method

    @property
    def code(self):
        if not hasattr(self, '_code'):
            words = self.headers[0].split(' ', 2)
            if words[0] == 'SIP/2.0':
                self._code = words[1]
            else:
                self._code = None
        return self._code

    @property
    def method_and_status(self):
        if self.code:
            return '%s(%s)' % (self.method, self.code)
        return self.method

    @property
    def callid(self):
        if not hasattr(self, '_callid'):
            self._callid = self.get_header('Call-ID', 'i')
        return self._callid

    @property
    def cseq(self):
        if not hasattr(self, '_cseq'):
            data = self.get_header('CSeq')
            if data:
                self._cseq = tuple(i.strip() for i in data.split(None, 1))
            else:
                self._cseq = (None, None)
        return self._cseq

    def get_header(self, header, alt=None):
        # FIXME: doesn't take line-folding into account!
        header = header.lower()
        if alt:
            alt = alt.lower()
        for line in self.headers[1:]:
            # Empty line? done with headers
            if line.strip() == '':
                break
            # Split by colon and match header
            try:
                word, rest = line.split(':', 1)
            except ValueError:
                print 'fail', line
                print self.headers
                assert False
            else:
                word = word.strip().lower()
                if word == header or (alt and word == alt):
                    return rest.strip()
        return None

    def search(self, re_grep):
        for line in self.headers:
            m = re_grep.search(line)
            if m:
                return m
        return None

IpPacket.register_subtype(SipPacket)


if __name__ == '__main__':
    # Simple test/example
    import datetime
    sip_packet = IpPacket.create(
        datetime.datetime.now(),
        'UDP',
        ('1.2.3.4', 1234),
        ('1.2.3.4', 1234),
        'INVITE sip:+123@1.2.3.4...\r\nCSeq: 667 INVITE\r\n'
    )
    assert isinstance(sip_packet, SipPacket), 'Packet is of type: %r' % (type(sip_packet),)
    assert sip_packet.cseq == ('667', 'INVITE'), 'CSeq is: %r' % (sip_packet.cseq,)
