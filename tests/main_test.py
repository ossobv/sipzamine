# vim: set ts=8 sw=4 sts=4 et ai tw=79:
# # -*- coding: utf-8 -*-
# sipzamine test case
# Copyright (C) 2020 Walter Doekes, OSSO B.V.
from __future__ import unicode_literals

from contextlib import contextmanager
from unittest import TestCase
from io import StringIO
import sys

from sipzamine.__main__ import main


@contextmanager
def redirect_stdout(new_target):  # py2 version, is in contextlib in py3
    old_target, sys.stdout = sys.stdout, new_target  # replace sys.stdout
    try:
        yield new_target  # run some code with the replaced stdout
    finally:
        sys.stdout = old_target  # restore to the previous value


@contextmanager
def redirect_stderr(new_target):  # py2 version, is in contextlib in py3
    old_target, sys.stderr = sys.stderr, new_target  # replace sys.stderr
    try:
        yield new_target  # run some code with the replaced stderr
    finally:
        sys.stderr = old_target  # restore to the previous value


class MainTestCase(TestCase):
    maxDiff = None

    def run_main(self, args):
        out, err, exc = StringIO(), StringIO(), None

        if sys.version_info >= (3,):
            # argparse in py3 expects unistrings
            correct_string_type_args = args
        else:
            # in py2 it expects binstrings
            correct_string_type_args = [i.encode('ascii') for i in args]

        with redirect_stdout(out), redirect_stderr(err):
            try:
                main(correct_string_type_args)
            except SystemExit as e:
                exc = e
        return out.getvalue(), err.getvalue(), exc

    def test_help(self):
        out, err, exc = self.run_main(['--help'])
        self.assertEqual(type(exc), SystemExit)
        self.assertEqual(exc.args, (0,))
        self.assertEqual(out, '''\
usage: sipzamine [-h] [--version] [--pcap filter] [--pmatch regex]
                 [--amatch regex] [--highlight regex] [--dateskew seconds]
                 [--mindate date] [--maxdate date] [--mindur seconds]
                 [--maxdur seconds] [--retransmits count] [--contents]
                 PCAP [PCAP ...]

Search and examine SIP transactions/dialogs

positional arguments:
  PCAP                  pcap files to parse

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --pcap filter, -p filter
                        pcap filter expression
  --pmatch regex, -m regex
                        any packet in dialog must match regex (can be used
                        multiple times), e.g. ^INVITE to match calls
  --amatch regex, -M regex
                        all packets in dialog must match regex (can be used
                        multiple times), e.g. ^(SIP/2.0|INVITE|BYE) to match
                        calls without an ACK
  --highlight regex, -H regex
                        highlight first matchgroup in packets (multiple
                        highlights are identified by letters a..z)
  --dateskew seconds    offset added to all dates, can be negative (use when
                        pcap clock was off)
  --mindate date        packets must be younger than specified date
  --maxdate date        packets must be older than specified date
  --mindur seconds      dialogs/transactions must be shorter than duration
  --maxdur seconds      dialogs/transactions must be longer than duration
  --retransmits count   at least count retransmits must be involved
  --contents            show complete packet contents
''')
        self.assertEqual(err, '')

    def test_basic_match(self):
        out, err, exc = self.run_main([
            'samples/dtmf_2833_1.pcap',
            'samples/sip-invites-with-utf8-and-latin1.pcap',
            '-m', '(1-26254|1-26272)@', '-H', 'From: "([^"]*)"'])
        self.assertEqual(exc, None)
        self.assertEqual(out, '''\
[ 1-26254@127.0.1.1 ]
2020-04-22 09:37:44.934771 127.0.1.1:5060 > 127.0.1.254:5060 1 INVITE <-- Dááve
2020-04-22 09:37:44.934941 127.0.1.254:5060 > 127.0.1.1:5060 1 INVITE(180) <-- Dááve
2020-04-22 09:37:44.936158 127.0.1.254:5060 > 127.0.1.1:5060 1 INVITE(200) <-- Dááve
2020-04-22 09:37:44.936408 127.0.1.1:5060 > 127.0.1.254:5060 1 ACK <-- Dááve
2020-04-22 09:37:45.942302 127.0.1.254:5060 > 127.0.1.1:5060 2 BYE <-- Bob
2020-04-22 09:37:45.942443 127.0.1.1:5060 > 127.0.1.254:5060 2 BYE(200) <-- Bob

[ 1-26272@127.0.1.1 ]
2020-04-22 09:38:08.846587 127.0.1.1:5060 > 127.0.1.254:5060 1 INVITE <-- D��ve
2020-04-22 09:38:08.846826 127.0.1.254:5060 > 127.0.1.1:5060 1 INVITE(180) <-- D��ve
2020-04-22 09:38:08.848031 127.0.1.254:5060 > 127.0.1.1:5060 1 INVITE(200) <-- D��ve
2020-04-22 09:38:08.848182 127.0.1.1:5060 > 127.0.1.254:5060 1 ACK <-- D��ve
2020-04-22 09:38:09.854283 127.0.1.254:5060 > 127.0.1.1:5060 2 BYE <-- Bob
2020-04-22 09:38:09.854407 127.0.1.1:5060 > 127.0.1.254:5060 2 BYE(200) <-- Bob

''')
        self.assertEqual(err, '''\
(utf-8 decode error near '...-26272-1-0\\r\\nFrom: "D<here->\\xe1\\xe1ve" <sip:service@1...')
(utf-8 decode error near '...-26272-1-0\\r\\nFrom: "D<here->\\xe1\\xe1ve" <sip:service@1...')
(utf-8 decode error near '...-26272-1-0\\r\\nFrom: "D<here->\\xe1\\xe1ve" <sip:service@1...')
(utf-8 decode error near '...26272-1-13\\r\\nFrom: "D<here->\\xe1\\xe1ve" <sip:service@1...')
(utf-8 decode error near '...23SIPpTag014\\r\\nTo: "D<here->\\xe1\\xe1ve" <sip:service@1...')
(utf-8 decode error near '...23SIPpTag014\\r\\nTo: "D<here->\\xe1\\xe1ve" <sip:service@1...')
''')

    def test_contents(self):
        out, err, exc = self.run_main([
            'samples/dtmf_2833_1.pcap',
            'samples/sip-invites-with-utf8-and-latin1.pcap',
            '-m', '(1-26254|1-26272)@', '--contents'])
        self.assertEqual(exc, None)
        self.assertEqual(out, '''\
[ 1-26254@127.0.1.1 ]
2020-04-22 09:37:44.934771 127.0.1.1:5060 > 127.0.1.254:5060 1 INVITE
  INVITE sip:+12345@127.0.1.254:5060 SIP/2.0\x0d
  Via: SIP/2.0/UDP 127.0.1.1:5060;branch=z9hG4bK-26254-1-0\x0d
  From: "Dááve" <sip:service@127.0.1.1:5060;tag=26254SIPpTag001>\x0d
  To: "Bob" <sip:+12345@127.0.1.254:5060>\x0d
  Call-ID: 1-26254@127.0.1.1\x0d
  CSeq: 1 INVITE\x0d
  Contact: sip:service@127.0.1.1:5060\x0d
  Content-Type: application/sdp\x0d
  Content-Length:   153\x0d
  \x0d
  v=0\x0d
  o=user1 53655765 2353687637 IN IP4 127.0.1.1\x0d
  s=-\x0d
  c=IN IP4 127.0.1.1\x0d
  t=0 0\x0d
  m=audio 6000 RTP/AVP 8 0\x0d
  a=rtpmap:8 PCMA/8000\x0d
  a=rtpmap:0 PCMU/8000\x0d
 \x20
2020-04-22 09:37:44.934941 127.0.1.254:5060 > 127.0.1.1:5060 1 INVITE(180)
  SIP/2.0 180 Ringing\x0d
  Via: SIP/2.0/UDP 127.0.1.1:5060;branch=z9hG4bK-26254-1-0\x0d
  From: "Dááve" <sip:service@127.0.1.1:5060;tag=26254SIPpTag001>\x0d
  To: "Bob" <sip:+12345@127.0.1.254:5060>;tag=26223SIPpTag013\x0d
  Call-ID: 1-26254@127.0.1.1\x0d
  CSeq: 1 INVITE\x0d
  Contact: sip:service@127.0.1.254:5060\x0d
  Content-Length: 0\x0d
  \x0d
 \x20
2020-04-22 09:37:44.936158 127.0.1.254:5060 > 127.0.1.1:5060 1 INVITE(200)
  SIP/2.0 200 OK\x0d
  Via: SIP/2.0/UDP 127.0.1.1:5060;branch=z9hG4bK-26254-1-0\x0d
  From: "Dááve" <sip:service@127.0.1.1:5060;tag=26254SIPpTag001>\x0d
  To: "Bob" <sip:+12345@127.0.1.254:5060>;tag=26223SIPpTag013\x0d
  Call-ID: 1-26254@127.0.1.1\x0d
  CSeq: 1 INVITE\x0d
  Contact: sip:service@127.0.1.254:5060\x0d
  Content-Type: application/sdp\x0d
  Content-Length:   157\x0d
  \x0d
  v=0\x0d
  o=user1 53655765 2353687637 IN IP4 127.0.1.254\x0d
  s=-\x0d
  c=IN IP4 127.0.1.254\x0d
  t=0 0\x0d
  m=audio 6000 RTP/AVP 8 0\x0d
  a=rtpmap:8 PCMA/8000\x0d
  a=rtpmap:0 PCMU/8000\x0d
 \x20
2020-04-22 09:37:44.936408 127.0.1.1:5060 > 127.0.1.254:5060 1 ACK
  ACK sip:service@127.0.1.254:5060 SIP/2.0\x0d
  Via: SIP/2.0/UDP 127.0.1.1:5060;branch=z9hG4bK-26254-1-13\x0d
  From: "Dááve" <sip:service@127.0.1.1:5060;tag=26254SIPpTag001>\x0d
  To: "Bob" <sip:+12345@127.0.1.254:5060>;;tag=26223SIPpTag013\x0d
  Call-ID: 1-26254@127.0.1.1\x0d
  CSeq: 1 ACK\x0d
  Contact: sip:service@127.0.1.1:5060\x0d
  Content-Length: 0\x0d
  \x0d
 \x20
2020-04-22 09:37:45.942302 127.0.1.254:5060 > 127.0.1.1:5060 2 BYE
  BYE sip:service@127.0.1.1:5060 SIP/2.0\x0d
  Via: SIP/2.0/UDP 127.0.1.254:5060;branch=z9hG4bK-26223-3-6\x0d
  From: "Bob" <sip:+12345@127.0.1.254:5060>;;tag=26223SIPpTag013\x0d
  To: "Dááve" <sip:service@127.0.1.1:5060;tag=26254SIPpTag001>\x0d
  Call-ID: 1-26254@127.0.1.1\x0d
  CSeq: 2 BYE\x0d
  Contact: sip:service@127.0.1.254:5060\x0d
  Content-Length: 0\x0d
  \x0d
 \x20
2020-04-22 09:37:45.942443 127.0.1.1:5060 > 127.0.1.254:5060 2 BYE(200)
  SIP/2.0 200 OK\x0d
  Via: SIP/2.0/UDP 127.0.1.254:5060;branch=z9hG4bK-26223-3-6\x0d
  From: "Bob" <sip:+12345@127.0.1.254:5060>;;tag=26223SIPpTag013\x0d
  To: "Dááve" <sip:service@127.0.1.1:5060;tag=26254SIPpTag001>\x0d
  Call-ID: 1-26254@127.0.1.1\x0d
  CSeq: 2 BYE\x0d
  Content-Length: 0\x0d
  \x0d
 \x20

[ 1-26272@127.0.1.1 ]
2020-04-22 09:38:08.846587 127.0.1.1:5060 > 127.0.1.254:5060 1 INVITE
  INVITE sip:+12345@127.0.1.254:5060 SIP/2.0\x0d
  Via: SIP/2.0/UDP 127.0.1.1:5060;branch=z9hG4bK-26272-1-0\x0d
  From: "D��ve" <sip:service@127.0.1.1:5060;tag=26272SIPpTag001>\x0d
  To: "Bob" <sip:+12345@127.0.1.254:5060>\x0d
  Call-ID: 1-26272@127.0.1.1\x0d
  CSeq: 1 INVITE\x0d
  Contact: sip:service@127.0.1.1:5060\x0d
  Content-Type: application/sdp\x0d
  Content-Length:   153\x0d
  \x0d
  v=0\x0d
  o=user1 53655765 2353687637 IN IP4 127.0.1.1\x0d
  s=-\x0d
  c=IN IP4 127.0.1.1\x0d
  t=0 0\x0d
  m=audio 6000 RTP/AVP 8 0\x0d
  a=rtpmap:8 PCMA/8000\x0d
  a=rtpmap:0 PCMU/8000\x0d
 \x20
2020-04-22 09:38:08.846826 127.0.1.254:5060 > 127.0.1.1:5060 1 INVITE(180)
  SIP/2.0 180 Ringing\x0d
  Via: SIP/2.0/UDP 127.0.1.1:5060;branch=z9hG4bK-26272-1-0\x0d
  From: "D��ve" <sip:service@127.0.1.1:5060;tag=26272SIPpTag001>\x0d
  To: "Bob" <sip:+12345@127.0.1.254:5060>;tag=26223SIPpTag014\x0d
  Call-ID: 1-26272@127.0.1.1\x0d
  CSeq: 1 INVITE\x0d
  Contact: sip:service@127.0.1.254:5060\x0d
  Content-Length: 0\x0d
  \x0d
 \x20
2020-04-22 09:38:08.848031 127.0.1.254:5060 > 127.0.1.1:5060 1 INVITE(200)
  SIP/2.0 200 OK\x0d
  Via: SIP/2.0/UDP 127.0.1.1:5060;branch=z9hG4bK-26272-1-0\x0d
  From: "D��ve" <sip:service@127.0.1.1:5060;tag=26272SIPpTag001>\x0d
  To: "Bob" <sip:+12345@127.0.1.254:5060>;tag=26223SIPpTag014\x0d
  Call-ID: 1-26272@127.0.1.1\x0d
  CSeq: 1 INVITE\x0d
  Contact: sip:service@127.0.1.254:5060\x0d
  Content-Type: application/sdp\x0d
  Content-Length:   157\x0d
  \x0d
  v=0\x0d
  o=user1 53655765 2353687637 IN IP4 127.0.1.254\x0d
  s=-\x0d
  c=IN IP4 127.0.1.254\x0d
  t=0 0\x0d
  m=audio 6000 RTP/AVP 8 0\x0d
  a=rtpmap:8 PCMA/8000\x0d
  a=rtpmap:0 PCMU/8000\x0d
 \x20
2020-04-22 09:38:08.848182 127.0.1.1:5060 > 127.0.1.254:5060 1 ACK
  ACK sip:service@127.0.1.254:5060 SIP/2.0\x0d
  Via: SIP/2.0/UDP 127.0.1.1:5060;branch=z9hG4bK-26272-1-13\x0d
  From: "D��ve" <sip:service@127.0.1.1:5060;tag=26272SIPpTag001>\x0d
  To: "Bob" <sip:+12345@127.0.1.254:5060>;;tag=26223SIPpTag014\x0d
  Call-ID: 1-26272@127.0.1.1\x0d
  CSeq: 1 ACK\x0d
  Contact: sip:service@127.0.1.1:5060\x0d
  Content-Length: 0\x0d
  \x0d
 \x20
2020-04-22 09:38:09.854283 127.0.1.254:5060 > 127.0.1.1:5060 2 BYE
  BYE sip:service@127.0.1.1:5060 SIP/2.0\x0d
  Via: SIP/2.0/UDP 127.0.1.254:5060;branch=z9hG4bK-26223-4-6\x0d
  From: "Bob" <sip:+12345@127.0.1.254:5060>;;tag=26223SIPpTag014\x0d
  To: "D��ve" <sip:service@127.0.1.1:5060;tag=26272SIPpTag001>\x0d
  Call-ID: 1-26272@127.0.1.1\x0d
  CSeq: 2 BYE\x0d
  Contact: sip:service@127.0.1.254:5060\x0d
  Content-Length: 0\x0d
  \x0d
 \x20
2020-04-22 09:38:09.854407 127.0.1.1:5060 > 127.0.1.254:5060 2 BYE(200)
  SIP/2.0 200 OK\x0d
  Via: SIP/2.0/UDP 127.0.1.254:5060;branch=z9hG4bK-26223-4-6\x0d
  From: "Bob" <sip:+12345@127.0.1.254:5060>;;tag=26223SIPpTag014\x0d
  To: "D��ve" <sip:service@127.0.1.1:5060;tag=26272SIPpTag001>\x0d
  Call-ID: 1-26272@127.0.1.1\x0d
  CSeq: 2 BYE\x0d
  Content-Length: 0\x0d
  \x0d
 \x20

''')
        self.assertEqual(err, '''\
(utf-8 decode error near '...-26272-1-0\\r\\nFrom: "D<here->\\xe1\\xe1ve" <sip:service@1...')
(utf-8 decode error near '...-26272-1-0\\r\\nFrom: "D<here->\\xe1\\xe1ve" <sip:service@1...')
(utf-8 decode error near '...-26272-1-0\\r\\nFrom: "D<here->\\xe1\\xe1ve" <sip:service@1...')
(utf-8 decode error near '...26272-1-13\\r\\nFrom: "D<here->\\xe1\\xe1ve" <sip:service@1...')
(utf-8 decode error near '...23SIPpTag014\\r\\nTo: "D<here->\\xe1\\xe1ve" <sip:service@1...')
(utf-8 decode error near '...23SIPpTag014\\r\\nTo: "D<here->\\xe1\\xe1ve" <sip:service@1...')
''')

    def test_dateskew(self):
        out, err, exc = self.run_main([
            'samples/dtmf_2833_1.pcap',
            'samples/sip-invites-with-utf8-and-latin1.pcap',
            '--dateskew', '59', '--maxdate', '2020-04-22 09:38:03'])
        self.assertEqual(exc, None)
        self.assertEqual(out, '''\
[ 1-26224@127.0.1.1 ]
2020-04-22 09:38:02.146407 127.0.1.1:5060 > 127.0.1.254:5060 1 INVITE
2020-04-22 09:38:02.146692 127.0.1.254:5060 > 127.0.1.1:5060 1 INVITE(180)
2020-04-22 09:38:02.147899 127.0.1.254:5060 > 127.0.1.1:5060 1 INVITE(200)
2020-04-22 09:38:02.148145 127.0.1.1:5060 > 127.0.1.254:5060 1 ACK

''')
        self.assertEqual(err, '')

    def test_p_none(self):
        out, err, exc = self.run_main([
            'samples/dtmf_2833_1.pcap',
            'samples/sip-invites-with-utf8-and-latin1.pcap',
            '-p', 'host 1.2.3.4'])
        self.assertEqual(exc, None)
        self.assertEqual(out, '')
        self.assertEqual(err, '')

    def test_p_all(self):
        out, err, exc = self.run_main([
            'samples/dtmf_2833_1.pcap',
            'samples/sip-invites-with-utf8-and-latin1.pcap',
            '-p', 'host 127.0.1.254'])
        self.assertEqual(exc, None)
        self.assertEqual(out, '''\
[ 1-26224@127.0.1.1 ]
2020-04-22 09:37:03.146407 127.0.1.1:5060 > 127.0.1.254:5060 1 INVITE
2020-04-22 09:37:03.146692 127.0.1.254:5060 > 127.0.1.1:5060 1 INVITE(180)
2020-04-22 09:37:03.147899 127.0.1.254:5060 > 127.0.1.1:5060 1 INVITE(200)
2020-04-22 09:37:03.148145 127.0.1.1:5060 > 127.0.1.254:5060 1 ACK
2020-04-22 09:37:04.150388 127.0.1.254:5060 > 127.0.1.1:5060 2 BYE
2020-04-22 09:37:04.150485 127.0.1.1:5060 > 127.0.1.254:5060 2 BYE(200)

[ 1-26242@127.0.1.1 ]
2020-04-22 09:37:20.613825 127.0.1.1:5060 > 127.0.1.254:5060 1 INVITE
2020-04-22 09:37:20.613993 127.0.1.254:5060 > 127.0.1.1:5060 1 INVITE(180)
2020-04-22 09:37:20.615178 127.0.1.254:5060 > 127.0.1.1:5060 1 INVITE(200)
2020-04-22 09:37:20.615375 127.0.1.1:5060 > 127.0.1.254:5060 1 ACK
2020-04-22 09:37:21.622186 127.0.1.254:5060 > 127.0.1.1:5060 2 BYE
2020-04-22 09:37:21.622317 127.0.1.1:5060 > 127.0.1.254:5060 2 BYE(200)

[ 1-26254@127.0.1.1 ]
2020-04-22 09:37:44.934771 127.0.1.1:5060 > 127.0.1.254:5060 1 INVITE
2020-04-22 09:37:44.934941 127.0.1.254:5060 > 127.0.1.1:5060 1 INVITE(180)
2020-04-22 09:37:44.936158 127.0.1.254:5060 > 127.0.1.1:5060 1 INVITE(200)
2020-04-22 09:37:44.936408 127.0.1.1:5060 > 127.0.1.254:5060 1 ACK
2020-04-22 09:37:45.942302 127.0.1.254:5060 > 127.0.1.1:5060 2 BYE
2020-04-22 09:37:45.942443 127.0.1.1:5060 > 127.0.1.254:5060 2 BYE(200)

[ 1-26272@127.0.1.1 ]
2020-04-22 09:38:08.846587 127.0.1.1:5060 > 127.0.1.254:5060 1 INVITE
2020-04-22 09:38:08.846826 127.0.1.254:5060 > 127.0.1.1:5060 1 INVITE(180)
2020-04-22 09:38:08.848031 127.0.1.254:5060 > 127.0.1.1:5060 1 INVITE(200)
2020-04-22 09:38:08.848182 127.0.1.1:5060 > 127.0.1.254:5060 1 ACK
2020-04-22 09:38:09.854283 127.0.1.254:5060 > 127.0.1.1:5060 2 BYE
2020-04-22 09:38:09.854407 127.0.1.1:5060 > 127.0.1.254:5060 2 BYE(200)

[ 1-26281@127.0.1.1 ]
2020-04-22 09:38:43.322572 127.0.1.1:5060 > 127.0.1.254:5060 1 INVITE
2020-04-22 09:38:43.322728 127.0.1.254:5060 > 127.0.1.1:5060 1 INVITE(180)
2020-04-22 09:38:43.323909 127.0.1.254:5060 > 127.0.1.1:5060 1 INVITE(200)
2020-04-22 09:38:43.324013 127.0.1.1:5060 > 127.0.1.254:5060 1 ACK
2020-04-22 09:38:44.330025 127.0.1.254:5060 > 127.0.1.1:5060 2 BYE
2020-04-22 09:38:44.330143 127.0.1.1:5060 > 127.0.1.254:5060 2 BYE(200)

''')
        self.assertEqual(err, '''\
(utf-8 decode error near '...-26272-1-0\\r\\nFrom: "D<here->\\xe1\\xe1ve" <sip:service@1...')
(utf-8 decode error near '...-26272-1-0\\r\\nFrom: "D<here->\\xe1\\xe1ve" <sip:service@1...')
(utf-8 decode error near '...-26272-1-0\\r\\nFrom: "D<here->\\xe1\\xe1ve" <sip:service@1...')
(utf-8 decode error near '...26272-1-13\\r\\nFrom: "D<here->\\xe1\\xe1ve" <sip:service@1...')
(utf-8 decode error near '...23SIPpTag014\\r\\nTo: "D<here->\\xe1\\xe1ve" <sip:service@1...')
(utf-8 decode error near '...23SIPpTag014\\r\\nTo: "D<here->\\xe1\\xe1ve" <sip:service@1...')
''')
