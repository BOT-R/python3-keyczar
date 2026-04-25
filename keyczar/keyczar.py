"""
Collection of Keyczar classes used to perform cryptographic functions:
encrypt and decrypt.

Simplified to remove signing/verifying, session encryption, and streaming
classes that are unused by the dentalemr-backend codebase.
"""
from __future__ import absolute_import

import io

from keyczar import errors
from keyczar import keydata
from keyczar import keyinfo
from keyczar import keys
from keyczar import readers
from keyczar import util
from keyczar import constants


class Keyczar(object):
  """Abstract Keyczar base class."""

  def __init__(self, reader):
    self.metadata = keydata.KeyMetadata.Read(reader.GetMetadata())
    self._keys = {}  # maps both KeyVersions and hash ids to keys
    self.primary_version = None
    self.default_size = self.metadata.type.default_size

    if not self.IsAcceptablePurpose(self.metadata.purpose):
      raise errors.KeyczarError("Unacceptable purpose: %s"
                                % self.metadata.purpose)

    for version in self.metadata.versions:
      if version.status == keyinfo.PRIMARY:
        if self.primary_version is not None:
          raise errors.KeyczarError(
              "Key sets may only have a single primary version")
        self.primary_version = version
      key = keys.ReadKey(self.metadata.type,
                         reader.GetKey(version.version_number))
      self._keys[version] = key
      self._AddHashedKey(key, key.hash_id)

  versions = property(lambda self: [k for k in self._keys.keys()
                                    if isinstance(k, keydata.KeyVersion)],
                      doc="""List of versions in key set.""")
  primary_key = property(lambda self: self.GetKey(self.primary_version),
                         doc="""The primary key for this key set.""")

  def __str__(self):
    return str(self.metadata)

  def _AddHashedKey(self, key, hash_id):
    if self._keys.get(hash_id) is None:
      self._keys[hash_id] = [key]
    else:
      self._keys[hash_id].append(key)

  def _ParseHeader(self, header):
    """Parse header, verify version, return matching key(s)."""
    version = bytearray(header)[0]
    if version != constants.VERSION:
      raise errors.BadVersionError(version)
    return self.GetKey(util.Base64WSEncode(header[1:]))

  def IsAcceptablePurpose(self, purpose):
    """Indicates whether purpose is valid. Abstract method."""

  def GetKey(self, key_id):
    """Return the key(s) associated with the given key_id."""
    try:
      return self._keys[key_id]
    except KeyError:
      raise errors.KeyNotFoundError(key_id)


class Encrypter(Keyczar):
  """Capable of encrypting only."""

  def IsAcceptablePurpose(self, purpose):
    return purpose == keyinfo.ENCRYPT or purpose == keyinfo.DECRYPT_AND_ENCRYPT

  def Encrypt(self, data, encoder=util.Base64WSEncode):
    """
    Encrypt data and return ciphertext (Base64 encoded by default).
    """
    reader = io.BufferedReader(io.BytesIO(util.RawBytes(data)))
    output = io.BytesIO()
    writer = io.BufferedWriter(output)
    self.EncryptIO(reader, writer)
    ciphertext = output.getvalue()
    return encoder(ciphertext) if encoder else ciphertext

  def EncryptIO(self, reader, writer):
    encrypting_key = self.primary_key
    if encrypting_key is None:
      raise errors.NoPrimaryKeyError()
    encrypting_key.EncryptIO(reader, writer)


class Crypter(Encrypter):
  """Capable of encrypting and decrypting."""

  def IsAcceptablePurpose(self, purpose):
    return purpose == keyinfo.DECRYPT_AND_ENCRYPT

  def Decrypt(self, ciphertext, decoder=util.Base64WSDecode):
    """
    Decrypt ciphertext and return plaintext.
    """
    data_bytes = decoder(ciphertext) if decoder else ciphertext
    reader = util.BytesReader(data_bytes)
    writer, getvalue = util.BytesWriter()

    self.DecryptIO(reader, writer)

    return util.RawString(getvalue())

  def DecryptIO(self, reader, writer):
    header = util.ReadLength(reader, constants.HEADER_SIZE)
    if len(header) < constants.HEADER_SIZE:
      raise errors.ShortCiphertextError(len(header))
    matchedkeys = self._ParseHeader(header)
    for key in matchedkeys:
      try:
        key.DecryptIO(header, reader, writer)
        return
      except errors.InvalidSignatureError:
        pass
      except Exception:
        pass

    raise errors.InvalidSignatureError()
