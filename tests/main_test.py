# vim: set ts=8 sw=4 sts=4 et ai tw=79:
# sipzamine test case
# Copyright (C) 2020 Walter Doekes, OSSO B.V.

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
    def run_main(self, args):
        out, err, exc = StringIO(), StringIO(), None
        with redirect_stdout(out), redirect_stderr(err):
            try:
                main(['--help'])
            except BaseException as e:
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
