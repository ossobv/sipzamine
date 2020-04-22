# vim: set ts=8 sw=4 sts=4 et ai tw=79:
# sipzamine test case
# Copyright (C) 2018,2020 Walter Doekes, OSSO B.V.

from unittest import TestCase
import subprocess
import sys


class FlakeTestCase(TestCase):
    def test_flake8(self):
        subprocess.check_output(['pip', 'install', 'flake8'])
        proc = subprocess.Popen(
            "find . -name '*.py' '!' -name 'argparse_1_2_1.py' | "
            "xargs '%s' -m flake8 --max-line-length=79 --max-complexity=10" % (
                sys.executable.replace("'", ''),),
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        out = out.decode('utf-8', 'replace')
        err = err.decode('utf-8', 'replace')
        if proc.wait() != 0:
            raise AssertionError(
                'flake8 check failed:\n{}\n{}\n'.format(out, err))
