#!/usr/bin/env python
# vim: set ts=8 sw=4 sts=4 et ai:
# SIP Pcap Parse Eye (sipcaparseye)
# Last Change: 2011-10-21 15:44
import re

# Matches dialogs and times and looks for certain info (EYE).
# Takes tcpdump -vs0 udp and port 5060 as input on stdin.


class Packet(object):
    @classmethod
    def create(self, time, from_, to, data):
        if not data:
            return Packet(time, from_, to, data)
        word = data[0].split(' ', 1)[0]
        if word in ('INVITE', 'ACK', 'BYE', 'CANCEL', 'NOTIFY', 'OPTIONS', 'REFER', 'REGISTER',
                'SUBSCRIBE', 'UPDATE', 'SIP/2.0'): # XXX: not exhaustive..
            return SipPacket(time, from_, to, data)
        return Packet(time, from_, to, data)
        
    def __init__(self, time, from_, to, data):
        self.time = time
        self.from_ = from_
        self.to = to
        self.data = data

    def __repr__(self):
        summary = 'empty'
        if self.data:
            summary = self.data[0][0:12] + '...'
        return '<Packet(%s, %s, %s, %s)>' % (self.time, self.from_, self.to, summary)


class SipPacket(Packet):
    # FIXME we should technically split __init__(data) into header and
    # body..

    # Aliases:
    # f:From
    # t:To
    # v:Via
    # s:Subject
    # l:Content-Length

    @property
    def method(self):
        if not hasattr(self, '_method'):
            word = self.data[0].split(' ', 1)[0]
            if word != 'SIP/2.0':
                self._method = word
            else:
                self._method = self.cseq[1]
        return self._method

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
                self._cseq = [i.strip() for i in data.split(None, 1)]
            else:
                self._cseq = [None, None]
        return self._cseq

    def get_header(self, header, alt=None):
        # FIXME doesn't take line-folding into account
        header = header.lower()
        if alt:
            alt = alt.lower()
        for line in self.data[1:]:
            # Empty line? done with headers
            if line.strip() == '':
                break
            # Split by colon and match header
            try:
                word, rest = line.split(':', 1)
            except ValueError:
                print 'fail', line
                print self.data
                assert False
            else:
                word = word.strip().lower()
                if word == header or (alt and word == alt):
                    return rest.strip()
        return None

    def search(self, re_grep):
        for line in self.data:
            m = re_grep.search(line)
            if m:
                return m
        return None


def pcapflat_to_packets(input):
    time_re = re.compile('^(\d{2}:\d{2}:\d{2}\.(\d+)).*$')
    from_to_re = re.compile('^    ([0-9.]+) > ([0-9.]+).*$')

    line = input.next()

    done = False
    while not done:
        m = time_re.match(line)
        assert m
        time = m.groups()[0]

        line = input.next()
        m = from_to_re.match(line)
        assert m
        from_ = m.groups()[0]
        to = m.groups()[1]

        # get all until eof or next packet
        data = []
        while not done:
            try:
                line = input.next()
            except StopIteration:
                done = True
                break
            if time_re.match(line):
                break
            else:
                data.append(line)
        # last line should contain TAB only
        if data and data[-1] == '\t\n':
            data.pop()

        # remove trailing LFs (CR was already removed by tcpdump -v
        data = [i[1:-1] for i in data]

        if data:
            yield Packet.create(time, from_, to, data)


def main(input, filter, show, err):
    # Use filter as show if show isn't supplied
    re_filter = re.compile(filter)
    re_show = re_filter
    if show:
        re_show = re.compile(show)

    # Aggregate packets into dialogs (FIXME: this could be a generator
    # which spits out dialogs as soon as they're finished
    # (BYE/CANCEL/4xx))
    dialogs = {}
    for packet in pcapflat_to_packets(input):
        if isinstance(packet, SipPacket):
            if packet.callid not in dialogs:
                dialogs[packet.callid] = []
            dialogs[packet.callid].append(packet)
        else:
            #print >>err, '(ignoring packet %r)' % (packet,)
            pass

    # Loop over dialogs, keeping only those which match
    matching_dialogs = []
    for dialogid, dialog in dialogs.iteritems():
        for packet in dialog:
            if packet.search(re_filter):
                matching_dialogs.append(dialog)
                break

    # Order dialogs by begin-time
    matching_dialogs.sort(key=lambda x: x[0].time)

    # Print the matching dialogs and show matches
    for packets in matching_dialogs:
        print '[', packets[0].callid, ']'
        for packet in packets:
            found_here = packet.search(re_show)
            if found_here:
                if not found_here.groups():
                    pointer = '<--'
                else:
                    pointer = '<-- %s' % (found_here.groups()[0],)
            else:
                pointer = ''
                
            print packet.time, packet.from_, '>', packet.to, packet.method, pointer
        print


if __name__ == '__main__':
    import sys

    if len(sys.argv) not in (2, 3):
        print >>sys.stderr, 'Usage: tcpdump -nnvs0 udp and port 5060 | %s FILTER_RE [SHOW_RE]' % (sys.argv[0],)
        sys.exit(1)

    main(sys.stdin, sys.argv[1], ''.join(sys.argv[2:3]), err=sys.stderr)

    # Example usage:
    #
    # # tcpdump -nnvs0 -r stored.pcap | sipcaparseye 'm=audio ([0-9]+) '
    #
    # Example usage and output:
    #
    # # for x in 5060.pcap.*; do tcpdump -vls0 -nnr $x; done 2>/dev/null | ./sipcaparseye.py '555338143' 'm=audio (\d+)'
    #
    # [ 100a2fae3cef080c2131ad43520aa864@217.21.192.80 ]
    # 13:55:58.436505 217.21.192.80.5060 > 217.21.192.81.5060 INVITE <-- 18494
    # 13:55:58.636605 217.21.192.81.5060 > 217.21.192.80.5060 INVITE 
    # 13:55:58.911068 217.21.192.81.5060 > 217.21.192.80.5060 INVITE 
    # 13:55:58.911204 217.21.192.81.5060 > 217.21.192.80.5060 INVITE <-- 13838
    # 13:55:58.912092 217.21.192.80.5060 > 217.21.192.81.5060 ACK 
    # 13:56:56.899586 217.21.192.80.5060 > 217.21.192.81.5060 BYE 
    # 13:56:56.899710 217.21.192.81.5060 > 217.21.192.80.5060 BYE 
    # 
    # [ 0b0d1540431f27a916ea20c036066f4e@217.21.192.81 ]
    # 13:55:58.650701 217.21.192.81.5060 > 213.247.123.20.5060 INVITE <-- 11396
    # 13:55:58.828700 213.247.123.20.5060 > 217.21.192.81.5060 INVITE 
    # 13:55:58.834821 213.247.123.20.5060 > 217.21.192.81.5060 INVITE <-- 31916
    # 13:55:58.910946 217.21.192.81.5060 > 213.247.123.20.5060 ACK 
    # 13:56:56.902392 217.21.192.81.5060 > 213.247.123.20.5060 BYE 
    # 13:56:56.909192 213.247.123.20.5060 > 217.21.192.81.5060 BYE 
    # 
    # [ 129d1e9429e11cfe5e5d6fde530b2ef5@217.21.192.80 ]
    # 13:57:13.634970 217.21.192.80.5060 > 217.21.192.81.5060 INVITE <-- 12690
    # 13:57:13.636740 217.21.192.81.5060 > 217.21.192.80.5060 INVITE 
    # 13:57:13.832023 217.21.192.81.5060 > 217.21.192.80.5060 INVITE 
    # 13:57:13.844603 217.21.192.81.5060 > 217.21.192.80.5060 INVITE <-- 13072
    # 13:57:13.845962 217.21.192.80.5060 > 217.21.192.81.5060 ACK 
    # 13:57:57.903778 217.21.192.80.5060 > 217.21.192.81.5060 BYE 
    # 13:57:57.903979 217.21.192.81.5060 > 217.21.192.80.5060 BYE 
    # 
    # [ 1190f008259869fb1b6d08731a69f93b@217.21.192.81 ]
    # 13:57:13.648555 217.21.192.81.5060 > 213.247.123.20.5060 INVITE <-- 17364
    # 13:57:13.831703 213.247.123.20.5060 > 217.21.192.81.5060 INVITE 
    # 13:57:13.841942 213.247.123.20.5060 > 217.21.192.81.5060 INVITE <-- 31916
    # 13:57:13.844446 217.21.192.81.5060 > 213.247.123.20.5060 ACK 
    # 13:57:57.907071 217.21.192.81.5060 > 213.247.123.20.5060 BYE 
    # 13:57:57.913785 213.247.123.20.5060 > 217.21.192.81.5060 BYE 
    # 
    # [ 4EA00CD7-00446313@DDUS0_PCU-004 ]
    # 13:58:15.215058 217.21.203.28.5060 > 217.21.192.81.5060 INVITE <-- 32486
    # 13:58:15.415958 217.21.192.81.5060 > 217.21.203.28.5060 INVITE 
    # 13:58:15.860498 217.21.192.81.5060 > 217.21.203.28.5060 INVITE 
    # 13:58:15.867087 217.21.192.81.5060 > 217.21.203.28.5060 INVITE <-- 18386
    # 13:58:15.894297 217.21.203.28.5060 > 217.21.192.81.5060 ACK 
    # 14:11:26.662720 217.21.192.81.5060 > 217.21.203.28.5060 BYE 
    # 14:11:26.717956 217.21.203.28.5060 > 217.21.192.81.5060 BYE 
    # 
    # [ 680e31bd2bc9f6890d0414f04a5e1048@217.21.192.81 ]
    # 13:58:15.642172 217.21.192.81.5060 > 213.247.123.20.5060 INVITE <-- 14588
    # 13:58:15.819623 213.247.123.20.5060 > 217.21.192.81.5060 INVITE 
    # 13:58:15.828833 213.247.123.20.5060 > 217.21.192.81.5060 INVITE <-- 31906
    # 13:58:15.866667 217.21.192.81.5060 > 213.247.123.20.5060 ACK 
    # 14:07:46.212420 213.247.123.20.5060 > 217.21.192.81.5060 INVITE <-- 31906
    # 14:07:46.240439 217.21.192.81.5060 > 213.247.123.20.5060 INVITE 
    # 14:07:46.240501 217.21.192.81.5060 > 213.247.123.20.5060 INVITE <-- 14588
    # 14:07:46.247745 213.247.123.20.5060 > 217.21.192.81.5060 ACK 
    # 14:11:26.658978 213.247.123.20.5060 > 217.21.192.81.5060 BYE 
    # 14:11:26.659146 217.21.192.81.5060 > 213.247.123.20.5060 BYE 
