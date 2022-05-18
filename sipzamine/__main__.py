# vim: set ts=8 sw=4 sts=4 et ai tw=79:
# sipzamine main (SIP Examine)
# Copyright (C) 2011-2015,2018,2020 Walter Doekes, OSSO B.V.
from __future__ import print_function, unicode_literals

from datetime import datetime, timedelta
from time import mktime, strptime
import codecs
import re
import sys

from . import sipzamine, __version__
from .argparse14191 import ArgumentParser14191
from .libdata import PcapReader
from .libprotosip import SipDialogs

try:
    cmp
except NameError:
    cmp = None  # FIXME: python3


class epochtime_without_date(object):
    """
    Magic float that ignores the date so time-only comparisons can be
    done.  Take care to ensure that in datetime comparisons, this object
    is on the LHS, so these overloaded __cmp__ operator can do its job.

    NOTE: We calculate the delta between daylight saving time in the initial
    value and the compared value ONLY ONCE.  This will produce crazy results
    around DST changes.  Also, around hour 00:00 we cannot guarantee any
    meaningful result either.  This is a quick hack that works in 95% of the
    cases.
    """
    def __init__(self, floatval):
        sys.stderr.write(
            '(warning: partial date parsing is inaccurate! use only if '
            'you know understand the limitations)\n')
        self.floatval = floatval
        self.dstdelta = None
        if cmp is None:
            raise NotImplementedError('py3')

    def __float__(self):
        return self.floatval

    def __cmp__(self, other):
        otherval = float(other)

        if self.dstdelta is None:
            self.dstdelta = (
                (datetime.fromtimestamp(otherval) -
                 datetime.utcfromtimestamp(otherval)).seconds -
                (datetime.fromtimestamp(self.floatval) -
                 datetime.utcfromtimestamp(self.floatval)).seconds
            )

        selfval = self.floatval % 86400.0
        otherval = (otherval + self.dstdelta) % 86400.0
        return cmp(selfval, otherval)


def my_dateskew(seconds):
    return timedelta(seconds=int(seconds))


def my_regex(regexstring):
    try:
        return re.compile(regexstring)
    except Exception:
        raise ValueError()


def my_strptime(timestring):
    for style, prefix in (
            ('%Y-%m-%d %H:%M:%S', ''),
            ('%Y-%m-%d %H:%M', ''),
            ('%Y-%m-%d', ''),
            ('%Y-%m-%d %H:%M:%S', '2000-01-01 '),
            ('%Y-%m-%d %H:%M', '2000-01-01 ')):
        try:
            parsed = strptime(prefix + timestring, style)
        except ValueError:
            pass
        else:
            ret = mktime(parsed)
            if prefix:
                ret = epochtime_without_date(ret)
            break
    else:
        raise ValueError(
            'Invalid time format; use YYYY-MM-DD '
            'HH:MM:SS or a shortened form')
    return ret


def my_timedelta(floatstring):
    if '.' in floatstring:
        # Add enough zeroes so the int value is large enough..
        floatstring = '0%s000000' % (floatstring,)
        num = [int(floatstring.split('.', 1)[0]),       # seconds
               int(floatstring.split('.', 1)[1][0:6])]  # milliseconds
    else:
        num = [int(floatstring),  # seconds
               0]                 # milliseconds
    if sum(num) == 0:
        raise ValueError('Specifying a zero time breaks boolean tests')
    return timedelta(seconds=num[0], milliseconds=num[1])


def parse_args(args):
    # Example: sipzamine -m '^INVITE' -H 'm=audio ([0-9]+)' \
    #                       -p 'host 1.2.3.4' 5060.pcap.00
    description = 'Search and examine SIP transactions/dialogs'
    parser = ArgumentParser14191(
        prog='sipzamine', description=description)
    parser.add_argument(
        '--version', action='version',
        version='%(prog)s {}'.format(__version__))

    parser.add_argument(
        'files', metavar='PCAP', nargs='+',
        help='pcap files to parse')
    parser.add_argument(
        '--pcap', '-p', metavar='filter',
        help='pcap filter expression')

    # FIXME: remark that the searches are performed on the header lines and
    # can be anchored as such
    parser.add_argument(
        '--pmatch', '-m', metavar='regex', action='append', type=my_regex,
        help=('any packet in dialog must match regex (can be used '
              'multiple times), e.g. ^INVITE to match calls'))
    # FIXME: we may need to tweak the --option-name here too, and the
    # description
    parser.add_argument(
        '--amatch', '-M', metavar='regex', action='append', type=my_regex,
        help='all packets in dialog must match regex (can be used '
             'multiple times), e.g. ^(SIP/2.0|INVITE|BYE) to match calls '
             'without an ACK')
    parser.add_argument(
        '--highlight', '-H', metavar='regex', action='append', type=my_regex,
        help=('highlight first matchgroup in packets (multiple '
              'highlights are identified by letters a..z)'))

    parser.add_argument(
        '--dateskew', metavar='seconds',
        default=timedelta(0), type=my_dateskew,
        help=('offset added to all dates, can be negative (use when pcap '
              'clock was off)'))

    parser.add_argument(
        '--mindate', metavar='date', type=my_strptime,
        help='packets must be younger than specified date')
    parser.add_argument(
        '--maxdate', metavar='date', type=my_strptime,
        help='packets must be older than specified date')

    parser.add_argument(
        '--mindur', metavar='seconds', type=my_timedelta,
        help='dialogs/transactions must be shorter than duration')
    parser.add_argument(
        '--maxdur', metavar='seconds', type=my_timedelta,
        help='dialogs/transactions must be longer than duration')

    parser.add_argument(
        '--retransmits', metavar='count', default=0, type=int,
        help='at least count retransmits must be involved')

    parser.add_argument(
        '--contents', action='store_true', default=False,
        help='show complete packet contents')

    return parser.parse_args(args)


def adjust_times(args):
    """
    Update the search dates according to the date skew
    """
    if args.dateskew:
        if args.mindate:
            args.mindate -= args.dateskew.total_seconds()
        if args.maxdate:
            args.maxdate -= args.dateskew.total_seconds()


def add_dialog_filters(sipdialogs, args):
    """
    Optionally add duration and search filters (try to put the light
    weight ones first)
    """
    if args.mindur:
        sipdialogs = sipzamine.minduration_filter(
            sipdialogs, min_duration=args.mindur)

    if args.maxdur:
        sipdialogs = sipzamine.maxduration_filter(
            sipdialogs, max_duration=args.maxdur)

    if args.amatch:
        for amatch in args.amatch:
            sipdialogs = sipzamine.allheaders_filter(
                    sipdialogs, header_match=amatch)
    if args.pmatch:
        for pmatch in args.pmatch:
            sipdialogs = sipzamine.anyheader_filter(
                sipdialogs, header_match=pmatch)

    if args.retransmits:
        sipdialogs = sipzamine.retransmits_filter(
            sipdialogs, count=args.retransmits)

    return sipdialogs


def app_main(args):
    opts = parse_args(args)
    adjust_times(opts)

    # Create a packet reader
    base_reader = reader = PcapReader(
        opts.files, pcap_filter=opts.pcap,
        min_date=opts.mindate, max_date=opts.maxdate)

    # Optionally add a date skew on the packets
    if opts.dateskew:
        reader = sipzamine.dateskew_filter(reader, skew=opts.dateskew)

    # Convert the packets into SIP dialogs
    reader = SipDialogs(reader)

    # Add filters
    reader = add_dialog_filters(reader, opts)

    # Call main with our pimped reader
    sipzamine.main(
        reader, packet_highlights=opts.highlight,
        show_contents=opts.contents)

    if base_reader.exit_error:
        sys.exit(1)

    return 0


def main():
    # All stdout is UTF-8 (unless we're writing binary).
    try:
        outfd = sys.stdout.detach()  # py3
    except AttributeError:
        outfd = sys.stdout  # py2
    sys.stdout = codecs.getwriter('utf-8')(outfd)

    return app_main(sys.argv[1:])


if __name__ == '__main__':
    sys.exit(main())

# Example usage:
#
# $ sipzamine -m 'sip:\+315' -H '^BYE' --pcap 'host banana' \
#                stored.pcap
# (or)
# $ /usr/sbin/tcpdump -nnvs0 -r stored.pcap host banana |
#       sipzamine -m 'sip:\+315' -H '^BYE' -
#
# Example output:
#
# [ 179978155f707e3622c0886752336210@22.22.22.22 ]
# 2011-11-23 22:27:20.746782 apple:5060 > banana:5060 102 INVITE
# 2011-11-23 22:27:20.747508 banana:5060 > apple:5060 102 INVITE(100)
# 2011-11-23 22:27:20.783424 banana:5060 > apple:5060 102 INVITE(200)
# 2011-11-23 22:27:20.783956 apple:5060 > banana:5060 102 ACK
# 2011-11-23 22:27:41.665581 apple:5060 > banana:5060 103 BYE <--
# 2011-11-23 22:27:41.665721 banana:5060 > apple:5060 103 BYE(200)
#
# [ 64e9278b4cdabb7c02f8c54f301937e7@apple ]
# 2011-11-23 22:28:16.875647 apple:5060 > banana:5060 102 INVITE
# 2011-11-23 22:28:16.876433 banana:5060 > apple:5060 102 INVITE(100)
# 2011-11-23 22:28:16.901755 banana:5060 > apple:5060 102 INVITE(200)
# 2011-11-23 22:28:16.902327 apple:5060 > banana:5060 102 ACK
# 2011-11-23 22:28:24.363193 apple:5060 > banana:5060 103 BYE <--
# 2011-11-23 22:28:24.363352 banana:5060 > apple:5060 103 BYE(200)
