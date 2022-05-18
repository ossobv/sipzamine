#!/usr/bin/env python
from distutils.core import setup

with open('README.rst') as file:
    long_description = file.read()


setup(
    name='sipzamine',
    version='0.7',
    entry_points={'console_scripts': ['sipzamine = sipzamine.__main__:main']},
    packages=['sipzamine'],
    data_files=[('share/doc/sipzamine', [
        'LICENSE.txt', 'README.rst', 'sipzamine/argparse-LICENSE.txt'])],
    description='SIP dialog examine utility (formerly sipcaparseye)',
    long_description=long_description,
    author='Walter Doekes, OSSO B.V.',
    author_email='wjdoekes+sipzamine@osso.nl',
    url='https://github.com/ossobv/sipzamine',
    license='GPLv3+',
    platforms=['linux'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: System Administrators',
        ('License :: OSI Approved :: GNU General Public License v3 '
         'or later (GPLv3+)'),
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Topic :: Communications :: Telephony',
        'Topic :: System :: Networking :: Monitoring',
    ],
    install_requires=[
        # pylibcap refuses to install easily using pip, use your
        # OS package manager if possible.
        # #'pylibcap ; python_version<"3"',
        # This one should work on py2 as well though.
        'pcapy ; python_version>="3"',
    ],
)

# vim: set ts=8 sw=4 sts=4 et ai tw=79:
