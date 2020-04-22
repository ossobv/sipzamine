# vim: set ts=8 sw=4 sts=4 et ai tw=79:
# sipzamine Base Protocol lib
# Copyright (C) 2011-2015,2020 Walter Doekes, OSSO B.V.
from __future__ import print_function, unicode_literals

import datetime


class IpPacket(object):
    '''
    IpPacket holds a TCP or UDP packet with data. Call IpPacket.create()
    when you're creating a new packet from data. It will search the list
    of registered refined types so you can get a subtype with more
    advanced methods instead.
    '''
    __types = []  # the list of registered subtypes

    @classmethod
    def create(cls, datetime, ip_proto, from_, to, data):
        '''
        Create a new IpPacket or, if possible, a refined subtype. Never
        call __init__ directly. Overriding this in your subclass doesn't
        make sense. This will be called anyway.
        '''
        # Create an IpPacket that will be returned if no one wants to
        # take it.
        default_packet = cls(datetime, ip_proto, from_, to, data)

        probabilities = []
        for type in cls.__types:
            probability = type.type_probability(default_packet)
            if probability != 0.0:
                probabilities.append((probability, type))

        if probabilities:
            probabilities.sort(key=lambda x: (-x[0], x[1].__name__))
            return probabilities[0][1](datetime, ip_proto, from_, to, data)

        return default_packet

    @classmethod
    def register_subtype(cls, class_):
        '''
        Register a new IpPacket subtype. Only subclasses of IpPacket may
        be registered.
        '''
        if not issubclass(class_, cls):
            raise TypeError('Not an IpPacket', class_)

        try:
            random_packet = IpPacket(datetime.datetime.now(), 'TCP',
                                     ('1.2.3.4', 1234), ('1.2.3.4', 1234), '')
            probability_check = class_.type_probability(random_packet)
            if not (0.0 <= probability_check <= 1.0):
                raise NotImplementedError()
        except NotImplementedError:
            raise TypeError('IpPacket subtype does not implement '
                            'type_probability() correctly: Expected a float '
                            'between 0 and 1')

        cls.__types.append(class_)

    @classmethod
    def type_probability(cls, datetime, ip_proto, from_, to, data):
        '''
        Return a number between 0.0 and 1.0 stating the probability that
        the packet is your type. We need to trust you on this. Don't let
        us down.
        '''
        raise NotImplementedError()

    def __init__(self, datetime, ip_proto, from_, to, data):
        self.datetime = datetime
        self.ip_proto = ip_proto
        self.from_ = from_
        self.to = to
        self.data = data

    def __repr__(self):
        summary = '(null)'
        if self.data:
            summary = self.data[0:12] + '...'
        return '<%s(%s, %s, %s, %s, %d B %r)>' % (
            self.__class__.__name__,
            self.datetime.strftime('%y%m%d:%H%M%S.%f'),
            self.ip_proto,
            self.from_,
            self.to,
            len(self.data),
            summary
        )


# # Simple test/example
# now = datetime.datetime.now()
# data = 'A bit of data'
# ip_packet = IpPacket.create(
#     now,
#     'TCP',
#     ('1.2.3.4', 1234),
#     ('1.2.3.4', 1234),
#     'A bit of data'
# )
# assert isinstance(ip_packet, IpPacket), \
#     'Packet is of type: %r' % (type(ip_packet),)
# assert ip_packet.datetime == now
# assert ip_packet.data == data
