sipzamine
=========

Command line SIP dialog matching and searching through offline PCAPs

TODO
----

- Add setup.py.
- Add versioning.
- Upload to PyPI.
- Add help text from https://code.osso.nl/projects/sipp.
- Rename binary from sipcaparseye to sipzamine?
- Add tests: begin with a smallish pcap.
- Do we need the libpcap dependency? Yes, we like -p => drop the
  VerbosePcapReader.
- Add the ability to write pcaps from the filter. Combine capability
  with sipscrub?
- Add license docs.
- Compare this to sipgrep (and other tools?). And homer?

See also:
---------

- https://github.com/ossobv/vcutil/blob/master/tcpdump247
