"""
Utility functions for keyczar package.

Rewritten to remove pycrypto/pyasn1 dependencies.
Uses only Python stdlib.
"""
from __future__ import division
from __future__ import absolute_import

import base64
import hmac as _hmac
import io
import os
import struct
import sys

from hashlib import sha1

from keyczar import errors as kzr_errors
from keyczar import constants

HLEN = sha1().digest_size  # 20 bytes

DEFAULT_STREAM_BUFF_SIZE = 4096


def RawString(b):
  if constants.IS_PYTHON_3 and isinstance(b, bytes):
    return b.decode(constants.DEFAULT_ENCODING)
  else:
    return b


def RawBytes(s):
  if constants.IS_PYTHON_3 and isinstance(s, str):
    return bytes(s, constants.DEFAULT_ENCODING)
  return s


def ByteOrd(s):
  return bytearray(s)[0]


def ByteChr(b):
  return bytes(bytearray([b]))


def BytesReader(b):
  return io.BufferedReader(io.BytesIO(b))


def BytesWriter():
  output = io.BytesIO()
  return (io.BufferedWriter(output), output.getvalue)


def ReadAll(reader):
  tempout = None
  output = b""
  while tempout is None or len(tempout) > 0:
    try:
      tempout = reader.read()
    except io.BlockingIOError:
      continue
    if tempout is None:
      continue
    output += tempout
  return output


def ReadLength(reader, length):
  buff = b""
  remaining = length
  while remaining != 0:
    try:
      temp = reader.read(remaining)
    except io.BlockingIOError:
      continue
    if temp is None:
      continue
    if len(temp) == 0:
      break
    buff += temp
    remaining -= len(temp)
  return buff


def RepeatByte(b, n):
  return bytes(bytearray([b for _ in range(n)]))


def RandBytes(n):
  return os.urandom(n)


def Hash(*inputs):
  """Return a SHA-1 hash over a variable number of inputs."""
  md = sha1()
  for i in inputs:
    md.update(i)
  return md.digest()


def PrefixHash(*inputs):
  """Return a SHA-1 hash over a variable number of length-prefixed inputs."""
  md = sha1()
  for i in inputs:
    md.update(IntToBytes(len(i)))
    md.update(i)
  return md.digest()


def ConstantTimeCompare(a, b):
  return _hmac.compare_digest(a, b)


BIG_ENDIAN_INT_SPECIFIER = ">i"
BIG_ENDIAN_LONG_LONG_SPECIFIER = ">q"


def IntToBytes(n):
  """Return byte string of 4 big-endian ordered bytes representing n."""
  return struct.pack(BIG_ENDIAN_INT_SPECIFIER, n)


def BytesToInt(n):
  return struct.unpack(BIG_ENDIAN_INT_SPECIFIER, n)[0]


def Base64WSEncode(b):
  """
  Return Base64 web safe encoding of b. Suppress padding characters (=).
  Uses URL-safe alphabet: - replaces +, _ replaces /.
  """
  return RawString(base64.urlsafe_b64encode(b)).replace("=", "")


def Base64WSDecode(s):
  """
  Return decoded version of given Base64 string. Ignore whitespace.
  Uses URL-safe alphabet: - replaces +, _ replaces /.
  """
  s = RawString(s)
  s = ''.join(s.splitlines())
  s = str(s.replace(" ", ""))
  d = len(s) % 4
  if d == 1:
    raise kzr_errors.Base64DecodingError()
  elif d == 2:
    s += "=="
  elif d == 3:
    s += "="

  s = RawBytes(s)
  try:
    return base64.urlsafe_b64decode(s)
  except TypeError:
    raise kzr_errors.Base64DecodingError()


def ReadFile(name):
  with open(name) as f:
    return f.read()


def WriteFile(data, loc):
  with open(loc, 'w') as f:
    f.write(data)
