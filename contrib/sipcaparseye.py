#!/usr/bin/env python
# vim: set ts=8 sw=4 sts=4 et ai:
# SIP Pcap Parse Eye (sipcaparseye) main
# Copyright (C) Walter Doekes, OSSO B.V. 2011

import re

from libdata import PcapReader, VerboseTcpdumpReader
from libprotosip import SipPacket # must import file so the type is registered

# FIXME: rename this to: sipzamin (sip examine)

# Matches dialogs and times and looks for certain info (EYE).
# Takes tcpdump -vs0 udp and port 5060 as input on stdin.


#def timediff(t0, t1):
#    seconds0 = t0.hour * 3600 + t0.minute * 60 + t0.second + t0.microsecond / 1000000.0
#    seconds1 = t1.hour * 3600 + t1.minute * 60 + t1.second + t1.microsecond / 1000000.0
#    return seconds1 - seconds0
    

def main(reader, filter, show, err):
    # FIXME: use lots of nice options!

    # Use filter as show if show isn't supplied
    re_filter = re.compile(filter)
    re_show = re_filter
    if show:
        re_show = re.compile(show)

    # Aggregate packets into dialogs (FIXME: this could be a generator
    # which spits out dialogs as soon as they're finished
    # (BYE/CANCEL/4xx))
    dialogs = {}
    for packet in reader:
        print packet
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
#            # HACKS!
#            if timediff(dialog[0].time, dialog[-1].time) > 2.0:
#                continue
#            if not dialog[0].from_.startswith('62'):
#                continue
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
                
            print packet.time, packet.from_, '>', packet.to, packet.cseq[0], packet.method_and_status, pointer
        print


if __name__ == '__main__':
    import sys

    # Example: tcpdump -nnvs0 -r stored.pcap | sipcaparseye 'm=audio ([0-9]+) '
    if len(sys.argv) not in (3, 4):
        print >>sys.stderr, 'Usage: tcpdump -nnvs0 udp and port 5060 | %s - FILTER_RE [SHOW_RE]' % (sys.argv[0],)
        sys.exit(1)

    if sys.argv[1] == '-':
        reader = VerboseTcpdumpReader(sys.stdin)
    else:
        reader = PcapReader(sys.argv[1])

    main(reader, sys.argv[2], ''.join(sys.argv[3:4]), err=sys.stderr)

    # Example usage:
    #
    # # tcpdump -nnvs0 -r stored.pcap | sipcaparseye - 'm=audio ([0-9]+) '
    #
    # Example usage and output:
    #
    # # for x in 5060.pcap.*; do tcpdump -vls0 -nnr $x; done 2>/dev/null | ./sipcaparseye.py - '555338143' 'm=audio (\d+)'
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
