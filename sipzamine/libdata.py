# vim: set ts=8 sw=4 sts=4 et ai tw=79:
# sipzamine Data source lib
# Copyright (C) 2011-2015,2018 Walter Doekes, OSSO B.V.

import datetime
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

from .libproto import IpPacket

if sys.version_info.major < 3:
    tobytes = bytearray  # mutable byte array, behaving like py3-bytes
else:
    tobytes = (lambda x: x)


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

        self.filenames = filenames
        self.pcap_filter = pcap_filter

        # This way we'll only need to watch out for a single exception when
        # iterating.
        class BogoPcap():
            def next(self):
                raise TypeError("'NoneType' object is not iterable")
        self.pcap = BogoPcap()

        self.min_date = min_date
        self.max_date = max_date

        self.filename = None
        self.link_type = None

        self.warnings = set()  # store what we've have warned about

    def __iter__(self):
        return self

    def __next__(self):
        while True:
            while True:
                # Re-open a new file until we have a packet
                try:
                    # Fetch the next entry or raise TypeError:
                    # "'NoneType' object is not iterable"
                    next_packet = self.pcap.next()

                    if len(next_packet) == 3:
                        # pylibpcap
                        (pktlen, data, timestamp) = next_packet
                    else:
                        # pcapy
                        (pkthdr, data) = next_packet
                        # pcapy returns (None, '') for the last packet
                        if pkthdr is None:
                            raise TypeError('EOF')
                        timestamp = pkthdr.getts()
                        timestamp = timestamp[0] + timestamp[1] * 0.000001

                except TypeError:
                    # Unfortunately, the python-libpcap library does not
                    # close any fd's. Looks like pcap_close() is never
                    # called (and calling _pcap.delete_pcapObject(...)
                    # ourselves does not help).
                    # This means that we have to rely on the OS for FD
                    # cleanup when finishing :(
                    self.pcap = None

                    # Are we done?
                    if not self.filenames:
                        raise StopIteration()

                    # Do we need a new file?
                    try:
                        self.pcap = pcap.pcapObject
                    except AttributeError:
                        # pcapy
                        self.filename = self.filenames.pop(0)
                        self.pcap = pcap.open_offline(self.filename)
                    else:
                        # pylibpcap
                        self.pcap = pcap.pcapObject()
                        self.filename = self.filenames.pop(0)
                        self.pcap.open_offline(self.filename)

                    if self.pcap_filter:
                        self.pcap.setfilter(self.pcap_filter, 0, 0)
                    # set link type, needed below
                    self.link_type = self.pcap.datalink()
                else:
                    break

            # On python2, convert to list-of-integers.
            data = tobytes(data)

            if self.min_date and self.min_date > timestamp:
                continue
            if self.max_date and self.max_date < timestamp:
                continue

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
            # No relevant data? Continue to next packet
            if data is None:
                continue

            version = data[0] >> 4
            header_len = (data[0] & 0x0f) << 2
            if version != 4:
                raise ValueError('How did you get a version %d in an IPv4 '
                                 'header?' % (version,))

            flags = data[6] >> 5
            fragment_offset = struct.unpack('>H', data[6:8])[0] & 0x1fff
            if flags & 2:
                msg = ('(packet defragmentation on t %f not implemented yet, '
                       'suppressing warning)')
                self.warn_once('more_fragments', msg % (timestamp,))
                # but, carry on
            if fragment_offset:
                msg = '(skipping IP fragment on t %f, suppressing warning)'
                self.warn_once('fragment', msg % (timestamp,))
                continue

            try:
                proto_num = data[9]
                ip_proto = self.protocols[proto_num]
            except KeyError:
                msg = ('(skipping unknown IP protocol %d on t %f, suppressing '
                       'warning)' % (proto_num, timestamp))
                self.warn_once('proto:%d' % (proto_num,), msg)
                continue

            from_ = socket.inet_ntoa(bytes(data[12:16]))
            to = socket.inet_ntoa(bytes(data[16:20]))

            # IP => TCP/UDP/ICMP/fragment
            data = data[header_len:]

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
    next = __next__

    def warn_once(self, key, message):
        if key not in self.warnings:
            sys.stderr.write(message + '\n')
            self.warnings.add(key)
