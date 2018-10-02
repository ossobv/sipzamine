sipzamine (previously sipcaparseye)
===================================

Command line SIP dialog matching and searching through offline PCAPs.

|pypi_version|



Installing
----------

.. code-block:: console

    $ sudo apt-get install python-libpcap  # or yum install..
    $ sudo pip install sipzamine



Example
-------

A basic example, finding all dialogs that last shorter than 1.5 seconds:

.. code-block:: console

    $ sipzamine -m ^BYE -H ^BYE --maxdur 1.5 --pcap 'host 22.22.22.22' stored.pcap
    [ 179978155f707e3622c0886752336210@22.22.22.22 ]
    2011-11-23 22:27:20.746782 22.22.22.22:5060 > 123.123.123.123:5060 102 INVITE
    2011-11-23 22:27:20.747508 123.123.123.123:5060 > 22.22.22.22:5060 102 INVITE(100)
    2011-11-23 22:27:20.783424 123.123.123.123:5060 > 22.22.22.22:5060 102 INVITE(200)
    2011-11-23 22:27:20.783956 22.22.22.22:5060 > 123.123.123.123:5060 102 ACK
    2011-11-23 22:27:21.665581 22.22.22.22:5060 > 123.123.123.123:5060 103 BYE <--
    2011-11-23 22:27:21.665721 123.123.123.123:5060 > 22.22.22.22:5060 103 BYE(200)



Command options
---------------

Normally you use ``-m`` to match a dialog by regular expression. And ``-p``
to filter by IP.

To highlight a particular text string in the concise output, use ``-H``.

Basic matching options:

.. code-block::

    --pcap filter, -p filter
        pcap filter expression
    --pmatch regex, -m regex
        any packet in dialog must match regex (can be used
        multiple times), e.g. ^INVITE to match calls
    --amatch regex, -M regex
        all packets in dialog must match regex (can be used
        multiple times), e.g. ^(SIP/2.0|INVITE|BYE) to match
        calls without an ACK

Output options:

.. code-block::

    --contents
        show complete packet contents
    --dateskew seconds
        offset added to all dates, can be negative (use when
        pcap clock was off)
    --highlight regex, -H regex
        highlight first matchgroup in packets (multiple
        highlights are identified by letters a..z)

Special dialog/packet matching options:

.. code-block::

    --mindate date
        packets must be younger than specified date
    --maxdate date
        packets must be older than specified date
    --mindur seconds
        dialogs/transactions must be shorter than duration
    --maxdur seconds
        dialogs/transactions must be longer than duration
    --retransmits count
        at least count retransmits must be involved



TODO
----

- Add tests: begin with a smallish pcap.
- Add the ability to write pcaps from the filter. Combine capability
  with sipscrub?
- Compare this to sipgrep (and other tools?). And homer?



Q & A
-----

How do I get ``pcap`` files?

  You're encouraged to always write SIP pcaps on your VoIP machine.
  tcpdump_ allows you easy rotation of pcaps so you won't run out of disk space.
  You can use the tcpdump247_ init script if you like.


.. _tcpdump: http://www.tcpdump.org/
.. _tcpdump247: https://github.com/ossobv/vcutil/blob/master/tcpdump247

.. |pypi_version| image:: https://img.shields.io/pypi/v/sipzamine.svg
    :target: https://pypi.python.org/pypi/sipzamine
