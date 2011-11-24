#!/usr/bin/env python
# vim: set ts=8 sw=4 sts=4 et ai:
# SIP Pcap Parse Eye (sipcaparseye) main
# Copyright (C) Walter Doekes, OSSO B.V. 2011

import re

from libdata import PcapReader, VerboseTcpdumpReader
from libprotosip import SipDialogs # must import file so the type is registered

# FIXME: rename this to: sipzamin (sip examine)

# TODO: the verbosereader should add CR's back.. now that we have the libpcapreader it should be deprecated too..

# Matches dialogs and times and looks for certain info (EYE).
# Takes tcpdump -vs0 udp and port 5060 as input on stdin.


def main(reader, filter, show, err):
    # FIXME: use lots of nice options!

    # Use filter as show if show isn't supplied
    re_filter = re.compile(filter)
    re_show = re_filter
    if show:
        re_show = re.compile(show)

    # Loop over dialogs, keeping those which match
    matching_dialogs = []
    for dialog in SipDialogs(reader):
        for packet in dialog:
#            # HACKS!
#            if (dialog[-1].datetime - dialog[0].time) > 2.0:
#                continue
#            if not dialog[0].from_[0].startswith('62'):
#                continue
            if packet.search(re_filter):
                matching_dialogs.append(dialog)
                break

    # Order dialogs by begin-time
    matching_dialogs.sort(key=lambda x: x[0].datetime)

    # Print the matching dialogs and show matches
    for dialog in matching_dialogs:
        print '[', dialog[0].callid, ']'
        for packet in dialog:
            found_here = packet.search(re_show)
            if found_here:
                if not found_here.groups():
                    pointer = '<--'
                else:
                    pointer = '<-- %s' % (found_here.groups()[0],)
            else:
                pointer = ''
                
            print packet.datetime, ':'.join(str(i) for i in packet.from_), '>', ':'.join(str(i) for i in packet.to), packet.cseq[0], packet.method_and_status, pointer
        print


if __name__ == '__main__':
    import sys
    try:
        import argparse
    except ImportError:
        import argparse_1_2_1 as argparse

    # Example: sipcaparseye -m '^INVITE' -H 'm=audio ([0-9]+)' -p 'host 1.2.3.4' 5060.pcap.00

    parser = argparse.ArgumentParser(description='Search and examine SIP transactions/dialogs')
    parser.add_argument('files', metavar='PCAP', nargs='+',
            help='pcap files to parse, or - to read tcpdump -nnvs0 output from stdin')
    parser.add_argument('--pcap', '-p', metavar='filter',
            help='pcap filter expression')
    parser.add_argument('--pmatch', '-m', metavar='regex',
            help='packet in dialog must match regex')
    parser.add_argument('--highlight', '-H', metavar='regex',
            help='highlight first matchgroup in packets')

    args = parser.parse_args()
    if len(args.files) == 1 and args.files[0] == '-':
        if args.pcap:
            parser.error('Cannot use pcap filter with stdin mode')
        reader = VerboseTcpdumpReader(sys.stdin)
    else:
        reader = PcapReader(args.files, args.pcap)
        
    main(reader, sys.argv[2], ''.join(sys.argv[3:4]), err=sys.stderr)

    # Example usage:
    #
    # $ sipcaparseye -m 'sip:\+315' -H 'm=audio +(\d+)' stored.pcap
    # (or)
    # $ /usr/sbin/tcpdump -nnvs0 -r stored.pcap | sipcaparseye -m 'sip:\+315' -H 'm=audio +(\d+)' -
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
