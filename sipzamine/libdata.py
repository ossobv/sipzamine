# vim: set ts=8 sw=4 sts=4 et ai tw=79:
# sipzamine Data source lib
# Copyright (C) 2011-2015,2018,2020-2022 Walter Doekes, OSSO B.V.
from __future__ import print_function, unicode_literals

import datetime
import os
import socket
import struct
import sys

try:
    import pcap  # python-libpcap
except ImportError:
    try:
        import pcapy as pcap
    except ImportError:
        if sys.version_info.major < 3:
            raise ImportError('Please apt install python-libpcap (pylibpcap)')
        raise ImportError('Please pip install pcapy (libpcap replacement)')
    else:
        PcapError = pcap.PcapError
else:
    class PcapError(ValueError):
        pass

from .libfile import extract_to_tempfile
from .libproto import IpPacket

if sys.version_info.major < 3:
    tobytes = bytearray  # mutable byte array, behaving like py3-bytes
else:
    tobytes = (lambda x: x)


class Skipping(BaseException):
    pass


class PcapReader(object):
    '''
    Reads a pcap file.
    '''
    protocols = {
        socket.IPPROTO_TCP: 'TCP',
        socket.IPPROTO_UDP: 'UDP',
        socket.IPPROTO_ICMP: 'ICMP'
    }

    def __init__(self, filenames, pcap_filter=None, min_date=None,
                 max_date=None):
        if not pcap:
            raise ImportError('PcapReader requires pylibpcap support '
                              '(python-libpcap)')

        self.warnings = set()  # store what we've have warned about

        # Add only valid (non-duplicate) filenames.
        self.filenames = []
        self.exit_error = 0
        for filename in filenames:
            if filename in self.filenames:
                msg = 'skipping duplicate filename %r' % (filename,)
                self.warn_once(msg, msg)
            else:
                try:
                    with open(filename, 'rb'):
                        pass
                except Exception:
                    msg = 'skipping unreadable file %r (error=1)' % (filename,)
                    self.warn_once(msg, msg)
                    self.exit_error = 1  # error at the end anyway
                else:
                    self.filenames.append(filename)

        self.pcap_filter = pcap_filter

        # This way we'll only need to watch out for a single exception when
        # iterating.
        class BogoPcap():
            def next(self):
                raise EOFError()
        self.pcap = BogoPcap()

        self.min_date = min_date
        self.max_date = max_date

        self.filename = None
        self.link_type = None

    def __iter__(self):
        return self

    def _get_next_packet(self):
        while True:
            # Re-open a new file until we have a packet
            try:
                next_packet = self.pcap.next()

                if next_packet is None:
                    # pylibpcap
                    raise EOFError()
                elif len(next_packet) == 3:
                    # pylibpcap
                    (pktlen, data, timestamp) = next_packet
                else:
                    # pcapy
                    (pkthdr, data) = next_packet
                    # pcapy returns (None, '') for the last packet
                    if pkthdr is None:
                        raise EOFError()
                    timestamp = pkthdr.getts()
                    timestamp = timestamp[0] + timestamp[1] * 0.000001

            except PcapError as e:
                msg = '%s: %s' % (self.filename, e)
                self.warn_once(msg, msg)
                self.exit_error = 1
                self._open_next_file()  # might EOF as well
            except EOFError:
                self._open_next_file()  # might EOF as well
            else:
                break

        # On python2, convert to list-of-integers.
        data = tobytes(data)

        return data, timestamp

    def _open_next_file(self):
        # In the past, python-libpcap did not clean up its fds. In
        # 0.6.4-1 it does though and the following is a no-op.
        self.pcap = None

        # Are we done?
        if not self.filenames:
            raise StopIteration()

        # Next file!
        self.filename = self.filenames.pop(0)
        # There is no pcap_fopen_offline(3pcap) call, so we'll
        # have to use a temp-file if the file was zipped.
        filename, is_tempfile = extract_to_tempfile(self.filename)

        try:
            self.pcap = pcap.pcapObject
        except AttributeError:
            # pcapy (raises pcapy.PcapError on read error)
            self.pcap = pcap.open_offline(filename)
        else:
            # pylibpcap
            self.pcap = pcap.pcapObject()
            self.pcap.open_offline(filename)

        if is_tempfile:
            os.unlink(filename)

        if self.pcap_filter:
            try:
                # pcapy 0.11.4: setfilter() takes exactly 1 argument
                self.pcap.setfilter(self.pcap_filter)
            except TypeError:
                # pylibpcap 0.6.4: pcapObject_setfilter()
                self.pcap.setfilter(self.pcap_filter, 0, 0)

        # Set link type, needed below
        self.link_type = self.pcap.datalink()

    def _get_frame_payload(self, data):
        # Get frame payload (pcap-linktype(7))
        # http://www.tcpdump.org/linktypes.html
        if self.link_type == pcap.DLT_RAW:  # Don't know??
            payload = data
        elif self.link_type == pcap.DLT_EN10MB:  # 0x1 Ethernet
            # to_mac = data[0:6]
            # from_mac = data[6:12]
            payload = data[12:]
        elif self.link_type == pcap.DLT_LINUX_SLL:  # 0x71 Linux Cooked SSL
            # packet_type = data[0:2]
            # arphdr_type = data[2:4]
            # lladdr_len = data[4:6] # =6 for mac
            # lladdr = data[6:14] # first 6 bytes for macaddr
            payload = data[14:]
        else:
            raise NotImplementedError(
                'Not implemented link type %d (0x%x) in %s' %
                (self.link_type, self.link_type, self.filename))

        return payload

    def _get_ethernet_data(self, payload):
        # Get ethernet data
        # http://en.wikipedia.org/wiki/EtherType
        data = None
        while True:
            if self.link_type == pcap.DLT_RAW:
                data = payload
                break
            elif payload[0:2] == b'\x08\x00':    # IPv4
                data = payload[2:]
                break
            elif payload[0:2] == b'\x81\x00':    # 802.1Q
                # tci = payload[2:2]  # pcp+cfi+vid
                payload = payload[4:]
                continue
            elif payload[0:2] == b'\x88\xa8':    # 802.1ad (Q-in-Q)
                raise NotImplementedError('VLAN-tagged ethernet frame '
                                          'decoding not implemented yet.')
            elif payload[0:2] == b'\x91\x00':    # 802.1QinQ (non-standard)
                raise NotImplementedError('VLAN-tagged ethernet frame '
                                          'decoding not implemented yet.')
            elif payload[0:2] == b'\x86\xdd':    # IPv6
                break  # ignore
            else:                                # Other stuff (like ARP)
                break  # ignore

        if data is None:
            raise Skipping()

        return data

    def _decode_ipv4(self, data, timestamp):
        version = data[0] >> 4
        header_len = (data[0] & 0x0f) << 2
        if version != 4:
            raise ValueError('How did you get a version %d in an IPv4 '
                             'header?' % (version,))

        flags = data[6] >> 5
        fragment_offset = struct.unpack('>H', data[6:8])[0] & 0x1fff
        if flags & 4:  # &1=(reserved) &2=DF, &4=MF
            msg = ('(packet defragmentation on t %f not implemented yet, '
                   'suppressing warning)')
            self.warn_once('more_fragments', msg % (timestamp,))
            # but, carry on
        if fragment_offset:
            msg = '(skipping IP fragment on t %f, suppressing warning)'
            self.warn_once('fragment', msg % (timestamp,))
            raise Skipping()

        try:
            proto_num = data[9]
            ip_proto = self.protocols[proto_num]
        except KeyError:
            msg = ('(skipping unknown IP protocol %d on t %f, suppressing '
                   'warning)' % (proto_num, timestamp))
            self.warn_once('proto:%d' % (proto_num,), msg)
            raise Skipping()

        from_ = socket.inet_ntoa(bytes(data[12:16]))
        to = socket.inet_ntoa(bytes(data[16:20]))

        # IP => TCP/UDP/ICMP/fragment
        body = data[header_len:]

        return from_, to, ip_proto, body

    def __next__(self):
        while True:
            try:
                data, timestamp = self._get_next_packet()

                if self.min_date and timestamp < self.min_date:
                    continue
                if self.max_date and timestamp >= self.max_date:  # exclusive
                    continue

                data = self._get_frame_payload(data)
                data = self._get_ethernet_data(data)
                from_, to, ip_proto, data = self._decode_ipv4(data, timestamp)
            except Skipping:
                continue

            if ip_proto in ('TCP', 'UDP'):
                from_ = (from_, struct.unpack('>H', data[0:2])[0])  # add port
                to = (to, struct.unpack('>H', data[2:4])[0])        # add port

                if ip_proto == 'TCP':
                    # FIXME: we need another layer for reassembling TCP
                    # into a stream before attempting to do app-protocol
                    # decoding on it.
                    data_offset = (data[12] >> 4) * 4
                    data = data[data_offset:]

                else:
                    data = data[8:]

            elif ip_proto == 'ICMP':
                # Parsing ICMP is nice if we want to trace port-
                # unreachable messages.
                msg = ('(skipping IP ICMP protocol on t %f, not yet '
                       'implemented, suppressing warning)')
                self.warn_once('proto:icmp', msg % (timestamp,))
                continue
            else:
                raise NotImplementedError(ip_proto)

            datetime_ = datetime.datetime.fromtimestamp(timestamp)
            return IpPacket.create(datetime_, ip_proto, from_, to, data)
    next = __next__  # py2

    def warn_once(self, key, message):
        if key not in self.warnings:
            sys.stderr.write(message + '\n')
            self.warnings.add(key)
