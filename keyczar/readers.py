"""
A Reader supports reading metadata and key info for key sets.

Simplified to retain only StaticKeyReader (the only reader used
by the dentalemr-backend codebase).
"""
from __future__ import absolute_import

from keyczar import keydata
from keyczar import keyinfo


class Reader(object):
  """Interface providing supported methods."""

  def GetMetadata(self):
    raise NotImplementedError

  def GetKey(self, version_number):
    raise NotImplementedError

  def Close(self):
    pass


class StaticKeyReader(Reader):
  """Reader that returns a static key."""

  def __init__(self, key, purpose):
    self._key = key
    self._meta = keydata.KeyMetadata("Imported", purpose, key.type)
    self._meta.AddVersion(keydata.KeyVersion(1, keyinfo.PRIMARY, False))

  def GetMetadata(self):
    return str(self._meta)

  def GetKey(self, version_number):
    return str(self._key)

  def Close(self):
    pass
