#!/usr/bin/env python
# vim: set ts=8 sw=4 sts=4 et ai:
# SIP Pcap Parse Eye (sipcaparseye) main
# Copyright (C) Walter Doekes, OSSO B.V. 2011

from libdata import PcapReader, VerboseTcpdumpReader
from libprotosip import SipDialogs # must import file so the type is registered

# Matches dialogs and times and looks for certain info (EYE).
# FIXME: rename this to: sipzamin (sip examine)
# TODO: the verbosereader should add CR's back.. now that we have the libpcapreader it should be deprecated too..


def dialog_filter(reader, packet_matches=None, min_duration=None, max_duration=None):
    for dialog in reader:
        # Filter against duration
        if min_duration or max_duration:
            duration = dialog[-1].datetime - dialog[0].datetime
            if min_duration and duration < min_duration:
                continue
            if max_duration and duration > max_duration:
                continue
        
        # Match dialogs by packet
        if packet_matches:
            matched = True
            for packet_match in packet_matches:
                # All matches must match
                for packet in dialog:
                    if packet.search(packet_match):
                        break
                else:
                    matched = False
                    break

            if not matched:
                continue
                    
        yield dialog
    
def print_dialog(dialog, packet_highlights=None):
    packet_highlights = packet_highlights or () # make sure its iterable

    print '[', dialog[0].callid, ']'
    for packet in dialog:
        highlights = []
        for i, packet_highlight in enumerate(packet_highlights):
            found_here = packet.search(packet_highlight)
            if found_here:
                if len(packet_highlights) == 1:
                    arrow = '<--'
                else:
                    arrow = '<-%s-' % (chr(ord('a') + i),)
                if not found_here.groups():
                    highlights.append(arrow)
                else:
                    highlights.append('%s %s' % (arrow, found_here.groups()[0]))
            
        print '%s %s:%d > %s:%d %s %s %s' % (
            packet.datetime, packet.from_[0], packet.from_[1], packet.to[0], packet.to[1],
            packet.cseq[0], packet.method_and_status, ' '.join(highlights)
        )
    print

def main(reader, packet_matches=None, packet_highlights=None, min_duration=None, max_duration=None):
    # Filter the dialogs
    matching_dialogs = []
    for dialog in dialog_filter(SipDialogs(reader), packet_matches, min_duration, max_duration):
        #print_dialog(dialog, packet_highlights)
        matching_dialogs.append(dialog)

    # Order dialogs by begin-time and first then print them
    matching_dialogs.sort(key=lambda x: x[0].datetime)
    for dialog in matching_dialogs:
        print_dialog(dialog, packet_highlights)


if __name__ == '__main__':
    import datetime, re, sys, time
    try:
        import argparse
    except ImportError:
        import argparse_1_2_1 as argparse

    def my_regex(regexstring):
        try:
            return re.compile(regexstring)
        except:
            raise ValueError()
    def my_strptime(timestring):
        return time.mktime(time.strptime(timestring, '%Y-%m-%d %H:%M:%S'))
    def my_timedelta(floatstring):
        if '.' in floatstring:
            floatstring = '0%s000000' % (floatstring,) # add enough zeroes so the int value is large enough
            num = [0, int(floatstring.split('.', 1)[0]), int(floatstring.split('.', 1)[1][0:6])]
        else:
            num = [0, int(floatstring), 0]
        if sum(num) == 0:
            raise ValueError('Now I cannot boolean test your value')
        return datetime.timedelta(*num)

    # Example: sipcaparseye -m '^INVITE' -H 'm=audio ([0-9]+)' -p 'host 1.2.3.4' 5060.pcap.00

    parser = argparse.ArgumentParser(description='Search and examine SIP transactions/dialogs')

    parser.add_argument('files', metavar='PCAP', nargs='+',
            help='pcap files to parse, or - to read tcpdump -nnvs0 output from stdin')
    parser.add_argument('--pcap', '-p', metavar='filter',
            help='pcap filter expression')

    parser.add_argument('--pmatch', '-m', metavar='regex', action='append', type=my_regex,
            help='packet in dialog must match regex (can be used multiple times)')
    parser.add_argument('--highlight', '-H', metavar='regex', action='append', type=my_regex,
            help='highlight first matchgroup in packets (multiple highlights are identified by letters a..z)')

    parser.add_argument('--mindate', metavar='date', type=my_strptime,
            help='packets must be younger than specified date')
    parser.add_argument('--maxdate', metavar='date', type=my_strptime,
            help='packets must be older than specified date')

    parser.add_argument('--mindur', metavar='seconds', type=my_timedelta,
            help='dialogs/transactions must be shorter than duration')
    parser.add_argument('--maxdur', metavar='seconds', type=my_timedelta,
            help='dialogs/transactions must be longer than duration')

    args = parser.parse_args()
    if len(args.files) == 1 and args.files[0] == '-':
        if args.pcap:
            parser.error('Cannot use pcap filter with stdin mode')
        reader = VerboseTcpdumpReader(sys.stdin, min_date=args.mindate, max_date=args.maxdate)
    else:
        reader = PcapReader(args.files, pcap_filter=args.pcap, min_date=args.mindate, max_date=args.maxdate)
        
    main(reader, packet_matches=args.pmatch, packet_highlights=args.highlight, min_duration=args.mindur, max_duration=args.maxdur)

    # Example usage:
    #
    # $ sipcaparseye -m 'sip:\+315' -H '^BYE' --pcap 'host 123.123.123.123' stored.pcap
    # (or)
    # $ /usr/sbin/tcpdump -nnvs0 -r stored.pcap host 123.123.123.123 | sipcaparseye -m 'sip:\+315' -H '^BYE' -
    #
    # Example output:
    #
    # [ 179978155f707e3622c0886752336210@22.22.22.22 ]
    # 2011-11-23 22:27:20.746782 22.22.22.22:5060 > 123.123.123.123:5060 102 INVITE 
    # 2011-11-23 22:27:20.747508 123.123.123.123:5060 > 22.22.22.22:5060 102 INVITE(100) 
    # 2011-11-23 22:27:20.783424 123.123.123.123:5060 > 22.22.22.22:5060 102 INVITE(200) 
    # 2011-11-23 22:27:20.783956 22.22.22.22:5060 > 123.123.123.123:5060 102 ACK 
    # 2011-11-23 22:27:41.665581 22.22.22.22:5060 > 123.123.123.123:5060 103 BYE <--
    # 2011-11-23 22:27:41.665721 123.123.123.123:5060 > 22.22.22.22:5060 103 BYE(200) 
    # 
    # [ 64e9278b4cdabb7c02f8c54f301937e7@22.22.22.22 ]
    # 2011-11-23 22:28:16.875647 22.22.22.22:5060 > 123.123.123.123:5060 102 INVITE 
    # 2011-11-23 22:28:16.876433 123.123.123.123:5060 > 22.22.22.22:5060 102 INVITE(100) 
    # 2011-11-23 22:28:16.901755 123.123.123.123:5060 > 22.22.22.22:5060 102 INVITE(200) 
    # 2011-11-23 22:28:16.902327 22.22.22.22:5060 > 123.123.123.123:5060 102 ACK 
    # 2011-11-23 22:28:24.363193 22.22.22.22:5060 > 123.123.123.123:5060 103 BYE <--
    # 2011-11-23 22:28:24.363352 123.123.123.123:5060 > 22.22.22.22:5060 103 BYE(200) 
