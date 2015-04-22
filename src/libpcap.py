#!/usr/bin/env python
# vim: set ts=8 sw=4 sts=4 et ai tw=79:
# sipzamine Pcap wrapper lib
# Copyright (C) 2015 Walter Doekes, OSSO B.V.
from datetime import datetime
from ctypes import (POINTER, Structure, byref, cdll, create_string_buffer,
                    c_char_p, c_long, c_ubyte, c_uint, c_void_p)
from ctypes.util import find_library


# The lib where our functions reside. This needs to stay open.
_pcaplib = cdll.LoadLibrary(find_library('pcap'))

PCAP_ERRBUF_SIZE = 256


def pcap_open_offline(fname):
    """
    pcap_open_offline() is called to open a ``savefile'' for reading.
    """
    errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
    res = _pcap_open_offline(fname, errbuf)
    if not res:
        raise ValueError(errbuf.value)
    return res

_pcap_open_offline = _pcaplib.pcap_open_offline
_pcap_open_offline.argtypes = (c_char_p, c_char_p)
_pcap_open_offline.restype = c_void_p


def pcap_close(p):
    """
    pcap_close() closes the files associated with p and deallocates resources.
    """
    _pcap_close(p)

_pcap_close = _pcaplib.pcap_close
_pcap_close.argtypes = (c_void_p,)
_pcap_close.restype = None


class _pcap_pkthdr(Structure):
    _fields_ = (("tv_sec", c_long), ("tv_usec", c_long),
                ("caplen", c_uint), ("len", c_uint))


def pcap_next(p):
    """
    pcap_next() reads the next packet from p and returns the following tuple:
    (datetime, data, total_len)

    datetime is in localtime, not UTC.
    data is an array of bytes.
    total_len is the length of the packet if it weren't trimmed by snaplen
    during capture.

    When done, it returns None.

    FIXME: on error.. something with pcap_geterr().
    """
    hdr = _pcap_pkthdr()
    res = _pcap_next(p, byref(hdr))
    if not res:
        return None

    assert hdr.caplen <= hdr.len  # capture length may be less

    # We could use utcfromtimestamp, but default tcpdump output uses localtime
    # too.
    datetime_ = datetime.fromtimestamp(float(hdr.tv_sec) +
                                       hdr.tv_usec / 1000000.0)
    data = res[0:hdr.caplen]
    total_len = hdr.len

    return (datetime_, data, total_len)

_pcap_next = _pcaplib.pcap_next
_pcap_next.argtypes = (c_void_p, c_void_p)
_pcap_next.restype = POINTER(c_ubyte)


def example(fname):
    handle = pcap_open_offline(fname)
    while True:
        data = pcap_next(handle)
        if not data:
            break
        print data

    pcap_close(handle)


if __name__ == '__main__':
    import sys
    example(sys.argv[1])

    # TODO:
    # (1) add filter-compile and filter-set
    # (2) add get-link-type
    # (3) replace sipzamine pcap stuff with this and remark that it does
    # close fd's
