# vim: set ts=8 sw=4 sts=4 et ai tw=79:
# sipzamine File reader lib
# Copyright (C) 2018,2020 Walter Doekes, OSSO B.V.
from __future__ import print_function, unicode_literals


def extract_to_tempfile(filename):
    has_tempfile = False

    if filename.endswith('.gz'):
        import gzip
        import tempfile

        gunzipped = tempfile.NamedTemporaryFile(delete=False)
        with gzip.open(filename, 'rb') as fp:
            gunzipped.write(fp.read())
        gunzipped.flush()
        has_tempfile = True
        filename = gunzipped.name

    return filename, has_tempfile
