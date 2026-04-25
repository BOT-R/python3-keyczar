"""
Keyczar is an open source cryptographic toolkit designed to make it easier and safer for developers to use cryptography in their applications. Keyczar supports authentication and encryption with both symmetric and asymmetric keys. Some features of Keyczar include:

* A simple API
* Key rotation and versioning
* Safe default algorithms, modes, and key lengths
* Automated generation of initialization vectors and ciphertext signatures
* Java, Python, and C++ implementations
* International support in Java (Python coming soon)

Keyczar was originally developed by members of the Google Security Team and is released under an Apache 2.0 license.
"""

from setuptools import setup
import sys

classifiers = """
Development Status :: 5 - Production/Stable
Intended Audience :: Developers
License :: OSI Approved :: Apache Software License
Programming Language :: Python
Programming Language :: Python :: 3
Topic :: Security
Topic :: Security :: Cryptography
Topic :: Software Development :: Libraries :: Python Modules
Operating System :: MacOS :: MacOS X
Operating System :: Microsoft :: Windows
Operating System :: Unix
"""

doclines = __doc__.split("\n")

extra = {}
# if sys.version_info >= (3,):
#     extra['use_2to3'] = True

setup(name='dmr-crypto',
      description='DentalEMR AES encryption (keyczar-compatible wire format)',
      author='DentalEMR',
      author_email='admin@dentalemr.com',
      version='1.0.0',
      packages=['keyczar'],
      install_requires=['cryptography>=3.1,<=41.0.7'],
      license='http://www.apache.org/licenses/LICENSE-2.0',
      platforms=['any'],
      classifiers=filter(None, classifiers.split("\n")),
      long_description=doclines[0],
      **extra
)
