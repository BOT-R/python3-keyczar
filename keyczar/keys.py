"""
Represents cryptographic keys in Keyczar.

Rewritten to use the `cryptography` library instead of pycrypto.
Only AES and HMAC-SHA1 key types are retained (RSA/DSA removed).
"""
from __future__ import division
from __future__ import absolute_import

import hmac as _hmac_mod
import json
import os

from hashlib import sha1

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from keyczar import errors
from keyczar import keyinfo
from keyczar import util
from keyczar import constants


class Key(object):
  """Parent class for Keyczar Keys."""

  def __init__(self, key_type):
    self.type = key_type
    self.__size = self.type.default_size

  def __eq__(self, other):
    return (self.type == other.type and
            self.size == other.size and
            self.key_string == other.key_string)

  def __SetSize(self, new_size):
    if self.type.IsValidSize(new_size):
      self.__size = new_size

  def _GetKeyString(self):
    """Return the key as a string. Abstract method."""

  def __GetKeyString(self):
    return self._GetKeyString()

  def _Hash(self):
    fullhash = util.PrefixHash(self.key_bytes)
    return util.Base64WSEncode(fullhash[:constants.KEY_HASH_SIZE])

  def __Hash(self):
    return self._Hash()

  hash_id = property(__Hash, doc="""The hash id of the key.""")
  size = property(lambda self: self.__size, __SetSize,
                  doc="""The size of the key in bits.""")
  key_string = property(__GetKeyString, doc="""The key as a Base64 string.""")
  key_bytes = property(lambda self: util.Base64WSDecode(self.key_string),
                       doc="""The key as bytes.""")

  def Header(self):
    """Return the 5-byte header: version byte + 4-byte key hash."""
    return (bytes(bytearray([constants.VERSION]))
            + util.Base64WSDecode(self.hash_id))


class SymmetricKey(Key):
  """Parent class for symmetric keys such as AES, HMAC-SHA1."""

  def __init__(self, key_type, key_string):
    Key.__init__(self, key_type)
    self.__key_string = key_string

  def _GetKeyString(self):
    return self.__key_string


class AesKey(SymmetricKey):
  """Represents AES symmetric private keys."""

  def __init__(self, key_string, hmac_key, size=keyinfo.AES.default_size,
               mode=keyinfo.CBC):
    SymmetricKey.__init__(self, keyinfo.AES, key_string)
    self.hmac_key = hmac_key
    self.block_size = 16  # AES block size is always 16
    self.size = size
    assert mode == keyinfo.CBC

  def __str__(self):
    return json.dumps({"mode": str(keyinfo.CBC),
                       "size": self.size,
                       "aesKeyString": self.key_string,
                       "hmacKey": json.loads(str(self.hmac_key))})

  def _Hash(self):
    fullhash = util.Hash(util.IntToBytes(len(self.key_bytes)),
                         self.key_bytes,
                         self.hmac_key.key_bytes)
    return util.Base64WSEncode(fullhash[:constants.KEY_HASH_SIZE])

  @staticmethod
  def Generate(size=keyinfo.AES.default_size):
    """Return a newly generated AES key."""
    key_bytes = util.RandBytes(size // 8)
    key_string = util.Base64WSEncode(key_bytes)
    hmac_key = HmacKey.Generate()
    return AesKey(key_string, hmac_key, size)

  @staticmethod
  def Read(key):
    """Read an AES key from a JSON string representation."""
    aes = json.loads(key)
    hmac_val = aes['hmacKey']
    return AesKey(aes['aesKeyString'],
                  HmacKey(hmac_val['hmacKeyString'], hmac_val['size']),
                  aes['size'], keyinfo.GetMode(aes['mode']))

  def _Pad(self, data):
    """Return data padded using PKCS5."""
    pad = self.block_size - len(data) % self.block_size
    return data + util.RepeatByte(pad, pad)

  def _UnPad(self, padded):
    """Return unpadded version of PKCS5-padded data."""
    pad = bytearray(padded)[-1]
    return padded[:-pad]

  def EncryptIO(self, reader, writer):
    """
    Encrypt from reader → writer.
    Output format: Header(5) | IV(16) | Ciphertext(padded) | HMAC-SHA1(20)
    """
    mac = self.hmac_key.CreateStreamable()

    # Write and MAC the header
    header = self.Header()
    writer.write(header)
    mac.Update(header)

    # Generate, write, and MAC the IV
    iv_bytes = util.RandBytes(self.block_size)
    writer.write(iv_bytes)
    mac.Update(iv_bytes)

    # Read all plaintext, pad it
    plaintext = util.ReadAll(reader)
    padded = self._Pad(plaintext)

    # Encrypt with AES-CBC using the cryptography library
    cipher = Cipher(algorithms.AES(self.key_bytes),
                    modes.CBC(iv_bytes),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    ciph_bytes = encryptor.update(padded) + encryptor.finalize()

    # MAC the ciphertext and write
    mac.Update(ciph_bytes)
    writer.write(ciph_bytes)

    # Write the MAC signature
    writer.write(mac.Sign())
    writer.flush()

  def DecryptIO(self, header, reader, writer):
    """
    Decrypt from reader → writer.
    Input after header: IV(16) | Ciphertext | HMAC-SHA1(20)
    Verifies HMAC before unpadding (prevents padding oracle attacks).
    """
    mac = self.hmac_key.CreateStreamable()

    # MAC the header
    mac.Update(header)

    # Read and MAC the IV
    iv_bytes = util.ReadLength(reader, self.block_size)
    mac.Update(iv_bytes)

    # Read all remaining data: ciphertext + signature
    remaining = util.ReadAll(reader)
    if len(remaining) < util.HLEN:
      raise errors.ShortCiphertextError(len(remaining))

    ciph_bytes = remaining[:-util.HLEN]
    sig_bytes = remaining[-util.HLEN:]

    # MAC the ciphertext
    mac.Update(ciph_bytes)

    # Verify HMAC BEFORE attempting to unpad
    if not util.ConstantTimeCompare(mac.Sign(), sig_bytes):
      raise errors.InvalidSignatureError()

    # Decrypt with AES-CBC
    cipher = Cipher(algorithms.AES(self.key_bytes),
                    modes.CBC(iv_bytes),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciph_bytes) + decryptor.finalize()

    # Unpad and write plaintext
    writer.write(self._UnPad(padded))
    writer.flush()


class HmacKey(SymmetricKey):
  """Represents HMAC-SHA1 symmetric private keys."""

  def __init__(self, key_string, size=keyinfo.HMAC_SHA1.default_size):
    SymmetricKey.__init__(self, keyinfo.HMAC_SHA1, key_string)
    self.size = size

  def __str__(self):
    return json.dumps({"size": self.size, "hmacKeyString": self.key_string})

  def _Hash(self):
    fullhash = util.Hash(self.key_bytes)
    return util.Base64WSEncode(fullhash[:constants.KEY_HASH_SIZE])

  def CreateStreamable(self):
    """Return a streaming version of this key."""
    return HmacKeyStream(self)

  @staticmethod
  def Generate(size=keyinfo.HMAC_SHA1.default_size):
    """Return a newly generated HMAC-SHA1 key."""
    key_bytes = util.RandBytes(size // 8)
    key_string = util.Base64WSEncode(key_bytes)
    return HmacKey(key_string, size)

  @staticmethod
  def Read(key):
    """Read an HMAC-SHA1 key from a JSON string."""
    mac = json.loads(key)
    return HmacKey(mac['hmacKeyString'], mac['size'])

  def Sign(self, msg):
    """Return raw byte string of HMAC-SHA1 signature on the message."""
    return _hmac_mod.new(self.key_bytes, msg, sha1).digest()

  def Verify(self, msg, sig_bytes):
    return self.VerifySignedData(self.Sign(msg), sig_bytes)

  def VerifySignedData(self, mac_bytes, sig_bytes):
    return util.ConstantTimeCompare(sig_bytes, mac_bytes)


class HmacKeyStream(object):
  """Represents streamable HMAC-SHA1 symmetric private keys."""

  def __init__(self, hmac_key):
    self.hmac_key = hmac_key
    self.hmac = _hmac_mod.new(self.hmac_key.key_bytes, b'', sha1)

  def Update(self, data):
    self.hmac.update(data)

  def Sign(self):
    """Return raw byte string of signature on the streamed message."""
    return self.hmac.digest()


def ReadKey(key_type, key):
  """Read a key of the given type from a JSON string."""
  try:
    return {keyinfo.AES: AesKey.Read,
            keyinfo.HMAC_SHA1: HmacKey.Read}[key_type](key)
  except KeyError:
    raise errors.KeyczarError("Unsupported key type: %s" % key_type)
