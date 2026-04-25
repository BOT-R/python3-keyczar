"""
Defines enums encoding information about keys: type, status, purpose,
and cipher mode.

Simplified to retain only AES/HMAC types (RSA/DSA removed).
"""
from __future__ import absolute_import

from keyczar import errors


class _NameId(object):
  def __init__(self, name, key_id):
    self.name = name
    self.id = key_id

  def __str__(self):
    return self.name


class KeyType(_NameId):
  """Encodes different key types and their properties."""

  sizes = property(lambda self: self.__sizes,
                   doc="""List of valid key sizes for this key type.""")

  def __init__(self, name, key_id, sizes):
    _NameId.__init__(self, name, key_id)
    self.__sizes = sizes
    self.default_size = self.__sizes[0]

  def IsValidSize(self, size):
    return size in self.__sizes


AES = KeyType("AES", 0, [128, 192, 256])
HMAC_SHA1 = KeyType("HMAC_SHA1", 1, [256])

__TYPES = {"AES": AES, "HMAC_SHA1": HMAC_SHA1}


def GetType(name):
  try:
    return __TYPES[name]
  except KeyError:
    raise errors.KeyczarError("Invalid Key Type")


class KeyStatus(_NameId):
  """Encodes the different possible statuses of a key."""


PRIMARY = KeyStatus("PRIMARY", 0)
ACTIVE = KeyStatus("ACTIVE", 1)
INACTIVE = KeyStatus("INACTIVE", 2)

__STATUSES = {"PRIMARY": PRIMARY, "ACTIVE": ACTIVE, "INACTIVE": INACTIVE}


def GetStatus(value):
  try:
    return __STATUSES[value]
  except KeyError:
    raise errors.KeyczarError("Invalid Key Status")


class KeyPurpose(_NameId):
  """Encodes the different possible purposes for a key."""


DECRYPT_AND_ENCRYPT = KeyPurpose("DECRYPT_AND_ENCRYPT", 0)
ENCRYPT = KeyPurpose("ENCRYPT", 1)
SIGN_AND_VERIFY = KeyPurpose("SIGN_AND_VERIFY", 2)
VERIFY = KeyPurpose("VERIFY", 3)

__PURPOSES = {
  "DECRYPT_AND_ENCRYPT": DECRYPT_AND_ENCRYPT,
  "ENCRYPT": ENCRYPT,
  "SIGN_AND_VERIFY": SIGN_AND_VERIFY,
  "VERIFY": VERIFY,
}


def GetPurpose(name):
  try:
    return __PURPOSES[name]
  except KeyError:
    raise errors.KeyczarError("Invalid Key Purpose")


class CipherMode(_NameId):
  """Encodes the different possible modes for a cipher."""

  def __init__(self, name, key_id, use_iv, output_size_fn):
    _NameId.__init__(self, name, key_id)
    self.use_iv = use_iv
    self.get_output_size = output_size_fn


CBC = CipherMode("CBC", 0, True, lambda b, i: (i / b + 2) * b)

__MODES = {"CBC": CBC}


def GetMode(name):
  try:
    return __MODES[name]
  except KeyError:
    raise errors.KeyczarError("Invalid Cipher Mode")
