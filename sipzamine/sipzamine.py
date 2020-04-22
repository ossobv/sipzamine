# vim: set ts=8 sw=4 sts=4 et ai tw=79:
# sipzamine main (SIP Examine)
# Copyright (C) 2011-2015,2018-2020 Walter Doekes, OSSO B.V.
from __future__ import print_function, unicode_literals

import re


def dateskew_filter(reader, skew):
    """
    Alter reader to shift all iterated object dates by dateskew.
    """
    for packet in reader:
        packet.datetime += skew
        yield packet


def minduration_filter(reader, min_duration):
    """
    Filter dialogs by minimum duration.
    """
    for dialog in reader:
        duration = dialog[-1].datetime - dialog[0].datetime
        if duration >= min_duration:
            yield dialog


def maxduration_filter(reader, max_duration):
    """
    Filter dialogs by maximum duration.
    """
    for dialog in reader:
        duration = dialog[-1].datetime - dialog[0].datetime
        if duration <= max_duration:
            yield dialog


def allheaders_filter(reader, header_match):
    """
    Filter dialogs by a regexp which must match all packets in the dialog.
    """
    for dialog in reader:
        for packet in dialog:
            if not packet.search(header_match):
                break
        else:
            yield dialog


def anyheader_filter(reader, header_match):
    """
    Filter dialogs by a regexp which must match any packet in the dialog.
    """
    for dialog in reader:
        for packet in dialog:
            if packet.search(header_match):
                yield dialog
                break


def retransmits_filter(reader, count):
    """
    Filter dialogs where at least count retransmits are observed.
    """
    assert count >= 1
    for dialog in reader:
        dupes = {}
        for packet in dialog:
            if packet.data not in dupes:
                dupes[packet.data] = 0
            else:
                dupes[packet.data] += 1
                if dupes[packet.data] >= count:
                    yield dialog
                    break


def print_dialog(dialog, packet_highlights=None, show_contents=False):
    packet_highlights = packet_highlights or ()  # make sure it's iterable
    if show_contents:
        data_munge = re.compile('^', re.MULTILINE)

    print('[ %s ]' % (dialog[0].callid,))
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
                    highlights.append('%s %s' %
                                      (arrow, found_here.groups()[0]))

        print(('%s %s:%d > %s:%d %s %s %s' % (
            packet.datetime, packet.from_[0], packet.from_[1],
            packet.to[0], packet.to[1],
            packet.cseq[0], packet.method_and_status, ' '.join(highlights)
        )).rstrip())

        if show_contents:
            print(data_munge.sub('  ', packet.data.decode('utf-8', 'replace')))

    print('')


def main(reader, packet_matches=None, packet_highlights=None,
         min_duration=None, max_duration=None, show_contents=False):
    # Filter the dialogs
    matching_dialogs = []
    for dialog in reader:
        # print_dialog(dialog, packet_highlights, show_contents=show_contents)
        matching_dialogs.append(dialog)

    # Order dialogs by begin-time and first then print them
    matching_dialogs.sort(key=lambda x: x[0].datetime)
    for dialog in matching_dialogs:
        print_dialog(dialog, packet_highlights, show_contents=show_contents)
