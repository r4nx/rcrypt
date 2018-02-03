import sys

from setuptools import setup
from setuptools.command.test import test as TestCommand

name = 'rcrypt'
version = '1.0.0'


class PyTest(TestCommand):
    user_options = [('pytest-args=', 'a', "Arguments to pass to pytest")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = ''

    def run_tests(self):
        import shlex
        import pytest
        errno = pytest.main(shlex.split(self.pytest_args))
        sys.exit(errno)


def readme():
    with open('README.rst') as f:
        return f.read()


setup(
    name=name,
    version=version,
    description='Wrapper for pycryptodomex',
    long_description=readme(),
    author='Ranx',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 3.6',
        'Topic :: Security :: Cryptography'
    ],
    license='GPLv3',
    packages=['rcrypt'],
    install_requires=['pycryptodomex'],
    tests_require=['pytest'],
    cmdclass={'test': PyTest}
)
