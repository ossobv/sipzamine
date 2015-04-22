# vim: set ts=8 sw=4 sts=4 et ai tw=79:
# sipzamine SIP Protocol lib
# Copyright (C) 2011-2015 Walter Doekes, OSSO B.V.

from collections import defaultdict

from .libproto import IpPacket


class SipPacket(IpPacket):
    @classmethod
    def type_probability(cls, packet):
        # TODO: up the probability if one of more of the ports are 5060
        if packet.data:
            word = packet.data.split(' ', 1)[0]
            if word in ('INVITE', 'ACK', 'BYE', 'CANCEL', 'NOTIFY', 'OPTIONS',
                        'PUBLISH', 'REFER', 'REGISTER', 'SUBSCRIBE', 'UPDATE',
                        'INFO', 'SIP/2.0'):  # XXX: not exhaustive..
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
                self._code = int(words[1])
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
                # Headers broken up too early? Can happen if we're
                # reading an UDP fragment or a TCP stream.. FIXME
                return None
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
        # FIXME: if body is not in headers, then we want to check body too
        return None

IpPacket.register_subtype(SipPacket)


class SipDialog(list):
    '''
    Container for a list of packets belonging to the same dialog.
    '''
    def append(self, item):
        super(SipDialog, self).append(item)
        if hasattr(self, '_is_established'):
            del self._is_established

    def is_established(self):
        if not hasattr(self, '_is_established'):
            cseqs_200 = []
            for i in self[1:]:
                if i.method == 'INVITE' and i.code == 200:
                    cseqs_200.append(i.cseq[0])
                elif i.method == 'ACK' and i.cseq[0] in cseqs_200:
                    self._is_established = True
                    break
            else:
                self._is_established = False
        return self._is_established


class SipDialogs(object):
    '''
    Read from a packet generator and yield SIP dialogs.
    '''
    def __init__(self, packet_generator):
        self.input = packet_generator
        self.dialogs = defaultdict(SipDialog)
        self.latest_datetime = None
        self.yieldable = []

    def __iter__(self):
        self.input = iter(self.input)
        return self

    def next(self):
        # Is there anything left to yield
        if self.yieldable:
            return self.yieldable.pop(0)

        # Are we done?
        if not self.input:
            raise StopIteration

        # Fetch more packets
        try:
            while True:
                packet = self.input.next()
                if isinstance(packet, SipPacket):
                    self.dialogs[packet.callid].append(packet)

                # Check if there is anything we can yield already based
                # on the latest timestamp (dialogs that are old enough
                # to end).
                # FIXME: sometimes we want this in a single dialog
                # (subscribes?)
                if (not self.latest_datetime or
                        ((packet.datetime - self.latest_datetime).seconds >
                         300)):
                    self.update_yieldable(packet.datetime)
                    self.latest_datetime = packet.datetime
                    if self.yieldable:
                        return self.yieldable.pop(0)

        except StopIteration:
            # Time to yield everything we have
            self.yieldable = self.dialogs.values()
            self.yieldable.sort(key=(lambda x: x[0].datetime))
            self.dialogs.clear()
            # self.input.close()
            self.input = None

        # Return the yieldables or raise StopIteration
        return self.next()

    def update_yieldable(self, latest_datetime):
        # Loop over dialogs, all non-INVITEs shan't be more than 120
        # seconds old. INVITEs may be older, but only if established.
        for k, v in self.dialogs.items():
            yield_it = False
            if (latest_datetime - v[-1].datetime).seconds > 120:
                # FIXME: subscribe establishes a long standing dialog as well
                if v[0].method != 'INVITE':
                    yield_it = True

                elif len(v) == 1 or v[-1].code:
                    # An INVITE without ACK as last packet.
                    yield_it = True

                elif (not v.is_established() and v[-1].method == 'ACK' and
                      v[-2].code >= 300):
                    # An INVITE dialog that failed and was ACKed.
                    yield_it = True

                elif (v.is_established() and v[-1].method == 'BYE' and
                      v[-1].code == 200):
                    # An INVITE dialog that has ended.
                    yield_it = True

                # Yield it?
                if yield_it:
                    self.yieldable.append(v)
                    del self.dialogs[k]

        # Prefer output to be sorted.. it won't be 100%, but it looks
        # better than nothing at all. If you want 100% sorting, I'm
        # afraid you'll have to do it at the end (buffering all).
        self.yieldable.sort(key=(lambda x: x[0].datetime))


# # Simple test/example
# import datetime
# sip_packet = IpPacket.create(
#     datetime.datetime.now(),
#     'UDP',
#     ('1.2.3.4', 1234),
#     ('1.2.3.4', 1234),
#     'INVITE sip:+123@1.2.3.4...\r\nCSeq: 667 INVITE\r\n'
# )
# assert isinstance(sip_packet, SipPacket), \
#     'Packet is of type: %r' % (type(sip_packet),)
# assert sip_packet.cseq == ('667', 'INVITE'), \
#     'CSeq is: %r' % (sip_packet.cseq,)
