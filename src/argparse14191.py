# vim: set ts=8 sw=4 sts=4 et ai tw=79:
# sipzamine Argparse wrapper
# Copyright (C) 2015 Walter Doekes, OSSO B.V.

try:
    from argparse import ArgumentParser
except ImportError:
    from .argparse_1_2_1 import ArgumentParser


class ArgumentParser14191(ArgumentParser):
    """ArgumentParser from argparse that handles out-of-order positional
    arguments.

    This is a workaround created by Glenn Linderman in July 2012. You
    can now do this:

        parser = ArgumentParser14191()
        parser.add_argument('-f', '--foo')
        parser.add_argument('cmd')
        parser.add_argument('rest', nargs='*')
        # some of these would fail with the regular parser:
        for args, res in (('-f1 cmd 1 2 3', 'ok'),
                          ('cmd -f1 1 2 3', 'would_fail'),
                          ('cmd 1 -f1 2 3', 'would_fail'),
                          ('cmd 1 2 3 -f1', 'ok')):
            try: out = parser.parse_args(args.split())
            except: print 'args', 'failed', res
            # out: Namespace(cmd='cmd', foo='1', rest=['1', '2', '3'])

    Bugs: http://bugs.python.org/issue14191
    Files: http://bugs.python.org/file26273/t18a.py
    Changes: renamed to ArgumentParser14191 ** PEP cleaned ** hidden
      ErrorParser inside ArgumentParser14191 ** documented ** used
      new-style classes super calls  (Walter Doekes, March 2015)
    """
    class ErrorParser(ArgumentParser):
        def __init__(self, *args, **kwargs):
            self.__errorobj = None
            super(ArgumentParser14191.ErrorParser, self).__init__(
                *args, add_help=False, **kwargs)

        def error(self, message):
            if self.__errorobj:
                self.__errorobj.error(message)
            else:
                ArgumentParser.error(self, message)

        def seterror(self, errorobj):
            self.__errorobj = errorobj

    def __init__(self, *args, **kwargs):
        self.__setup = False
        self.__opt = ArgumentParser14191.ErrorParser(*args, **kwargs)
        super(ArgumentParser14191, self).__init__(*args, **kwargs)
        self.__opt.seterror(self)
        self.__setup = True

    def add_argument(self, *args, **kwargs):
        super(ArgumentParser14191, self).add_argument(*args, **kwargs)
        if self.__setup:
            chars = self.prefix_chars
            if args and len(args[0]) and args[0][0] in chars:
                self.__opt.add_argument(*args, **kwargs)

    def parse_args(self, args=None, namespace=None):
        ns, remain = self.__opt.parse_known_args(args, namespace)
        ns = super(ArgumentParser14191, self).parse_args(remain, ns)
        return ns
