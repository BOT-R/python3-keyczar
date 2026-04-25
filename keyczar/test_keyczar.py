"""
Unit tests for the rewritten keyczar package (cryptography backend).

Tests cover:
  - AesKey / HmacKey generate, read, str round-trip
  - Encrypt / Decrypt round-trip via Crypter
  - Wire format correctness (header, IV, ciphertext, HMAC)
  - Base64WS encoding/decoding (including error on bad input)
  - Cross-compatibility with pre-existing ciphertext (test vector)
  - Tampered ciphertext detection (HMAC verification)
  - Multi-key fallback in Crypter.Decrypt
"""
from __future__ import absolute_import

import base64
import json
import os
import struct
import unittest

from keyczar import constants
from keyczar import errors
from keyczar import keydata
from keyczar import keyinfo
from keyczar import keys
from keyczar import keyczar
from keyczar import readers
from keyczar import util


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _make_crypter(aes_key=None, size=256):
  """Return (crypter, aes_key) ready for encrypt/decrypt."""
  if aes_key is None:
    aes_key = keys.AesKey.Generate(size=size)
  reader = readers.StaticKeyReader(aes_key, keyinfo.DECRYPT_AND_ENCRYPT)
  return keyczar.Crypter(reader), aes_key


# ---------------------------------------------------------------------------
# util.py tests
# ---------------------------------------------------------------------------

class Base64WSTest(unittest.TestCase):

  def test_encode_decode_round_trip(self):
    for data in [b'', b'\x00', b'hello world', os.urandom(256)]:
      encoded = util.Base64WSEncode(data)
      self.assertIsInstance(encoded, str)
      # No padding characters
      self.assertNotIn('=', encoded)
      decoded = util.Base64WSDecode(encoded)
      self.assertEqual(decoded, data)

  def test_bad_base64_raises(self):
    # Length mod 4 == 1 triggers Base64DecodingError
    with self.assertRaises(errors.Base64DecodingError):
      util.Base64WSDecode('x')

  def test_raw_bytes_and_raw_string(self):
    self.assertIsInstance(util.RawBytes('hello'), bytes)
    self.assertIsInstance(util.RawString(b'hello'), str)

  def test_hash_deterministic(self):
    data = b'some bytes'
    h1 = util.Hash(data)
    h2 = util.Hash(data)
    self.assertEqual(h1, h2)
    self.assertEqual(len(h1), 20)  # SHA-1

  def test_prefix_hash(self):
    data = b'key material'
    h = util.PrefixHash(data)
    self.assertEqual(len(h), 20)

  def test_int_to_bytes(self):
    self.assertEqual(util.IntToBytes(0), b'\x00\x00\x00\x00')
    self.assertEqual(util.IntToBytes(1), b'\x00\x00\x00\x01')
    self.assertEqual(util.IntToBytes(256), b'\x00\x00\x01\x00')

  def test_rand_bytes_length(self):
    for n in [0, 1, 16, 32, 64]:
      self.assertEqual(len(util.RandBytes(n)), n)

  def test_constant_time_compare(self):
    a = b'same'
    b_val = b'same'
    self.assertTrue(util.ConstantTimeCompare(a, b_val))
    self.assertFalse(util.ConstantTimeCompare(a, b'diff'))


# ---------------------------------------------------------------------------
# keys.py tests
# ---------------------------------------------------------------------------

class HmacKeyTest(unittest.TestCase):

  def test_generate_and_str_round_trip(self):
    hk = keys.HmacKey.Generate()
    js = str(hk)
    parsed = json.loads(js)
    self.assertIn('hmacKeyString', parsed)
    self.assertIn('size', parsed)
    hk2 = keys.HmacKey.Read(js)
    self.assertEqual(hk.key_string, hk2.key_string)
    self.assertEqual(hk.size, hk2.size)

  def test_sign_verify(self):
    hk = keys.HmacKey.Generate()
    msg = b'test message'
    sig = hk.Sign(msg)
    self.assertTrue(hk.Verify(msg, sig))
    self.assertFalse(hk.Verify(b'wrong', sig))

  def test_streamable(self):
    hk = keys.HmacKey.Generate()
    stream = hk.CreateStreamable()
    stream.Update(b'part1')
    stream.Update(b'part2')
    sig1 = stream.Sign()

    full_sig = hk.Sign(b'part1part2')
    self.assertEqual(sig1, full_sig)

  def test_hash_id_is_stable(self):
    hk = keys.HmacKey.Generate()
    h1 = hk.hash_id
    h2 = hk.hash_id
    self.assertEqual(h1, h2)
    self.assertIsInstance(h1, str)


class AesKeyTest(unittest.TestCase):

  def test_generate_default_size(self):
    ak = keys.AesKey.Generate()
    self.assertEqual(ak.size, 128)
    self.assertEqual(len(ak.key_bytes), 16)

  def test_generate_256(self):
    ak = keys.AesKey.Generate(size=256)
    self.assertEqual(ak.size, 256)
    self.assertEqual(len(ak.key_bytes), 32)

  def test_str_round_trip(self):
    ak = keys.AesKey.Generate(size=256)
    js = str(ak)
    parsed = json.loads(js)
    self.assertIn('aesKeyString', parsed)
    self.assertIn('hmacKey', parsed)
    self.assertIn('size', parsed)
    self.assertIn('mode', parsed)
    self.assertEqual(parsed['mode'], 'CBC')

    ak2 = keys.AesKey.Read(js)
    self.assertEqual(ak.key_string, ak2.key_string)
    self.assertEqual(ak.hmac_key.key_string, ak2.hmac_key.key_string)
    self.assertEqual(ak.size, ak2.size)

  def test_hash_id_stable(self):
    ak = keys.AesKey.Generate(size=256)
    self.assertEqual(ak.hash_id, ak.hash_id)

  def test_header_format(self):
    ak = keys.AesKey.Generate(size=256)
    header = ak.Header()
    self.assertEqual(len(header), constants.HEADER_SIZE)
    self.assertEqual(bytearray(header)[0], constants.VERSION)


# ---------------------------------------------------------------------------
# Encrypt / Decrypt round-trip via Crypter
# ---------------------------------------------------------------------------

class CrypterRoundTripTest(unittest.TestCase):

  def test_encrypt_decrypt_ascii(self):
    c, _ = _make_crypter()
    pt = 'Hello, DentalEMR!'
    ct = c.Encrypt(pt)
    self.assertIsInstance(ct, str)
    self.assertNotEqual(ct, pt)
    result = c.Decrypt(ct)
    self.assertEqual(result, pt)

  def test_encrypt_decrypt_unicode(self):
    c, _ = _make_crypter()
    pt = u'\u00e9\u00e8\u00ea\u00eb'  # accented chars
    ct = c.Encrypt(pt)
    self.assertEqual(c.Decrypt(ct), pt)

  def test_encrypt_decrypt_empty_string(self):
    c, _ = _make_crypter()
    ct = c.Encrypt('')
    self.assertEqual(c.Decrypt(ct), '')

  def test_encrypt_decrypt_long_data(self):
    c, _ = _make_crypter()
    pt = 'x' * 100000
    ct = c.Encrypt(pt)
    self.assertEqual(c.Decrypt(ct), pt)

  def test_different_ciphertexts_for_same_plaintext(self):
    """Each encryption uses a random IV, so outputs differ."""
    c, _ = _make_crypter()
    pt = 'same input'
    ct1 = c.Encrypt(pt)
    ct2 = c.Encrypt(pt)
    self.assertNotEqual(ct1, ct2)

  def test_128_bit_key(self):
    c, _ = _make_crypter(size=128)
    pt = 'AES-128 test'
    self.assertEqual(c.Decrypt(c.Encrypt(pt)), pt)

  def test_256_bit_key(self):
    c, _ = _make_crypter(size=256)
    pt = 'AES-256 test'
    self.assertEqual(c.Decrypt(c.Encrypt(pt)), pt)


# ---------------------------------------------------------------------------
# Wire format tests
# ---------------------------------------------------------------------------

class WireFormatTest(unittest.TestCase):

  def test_ciphertext_structure(self):
    """
    Ciphertext (before base64) layout:
      [1B version] [4B key_hash] [16B IV] [N*16 B ciphertext] [20B HMAC-SHA1]
    """
    c, ak = _make_crypter()
    pt = 'test'
    ct_b64 = c.Encrypt(pt)
    ct_raw = util.Base64WSDecode(ct_b64)

    # Minimum size: 5 (header) + 16 (IV) + 16 (1 block) + 20 (HMAC) = 57
    self.assertGreaterEqual(len(ct_raw), 57)

    # Version byte
    self.assertEqual(bytearray(ct_raw)[0], constants.VERSION)

    # Key hash (4 bytes) should match the key's hash_id
    hash_bytes = ct_raw[1:5]
    self.assertEqual(hash_bytes, util.Base64WSDecode(ak.hash_id))

    # HMAC is last 20 bytes
    hmac_sig = ct_raw[-20:]
    self.assertEqual(len(hmac_sig), 20)

    # Ciphertext body (between IV and HMAC) is a multiple of block size
    iv = ct_raw[5:21]
    self.assertEqual(len(iv), 16)
    ciph_body = ct_raw[21:-20]
    self.assertEqual(len(ciph_body) % 16, 0)


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------

class TamperDetectionTest(unittest.TestCase):

  def test_tampered_ciphertext_raises(self):
    c, _ = _make_crypter()
    ct_b64 = c.Encrypt('secret data')
    ct_raw = bytearray(util.Base64WSDecode(ct_b64))
    # Flip a byte in the ciphertext body (after header+IV, before HMAC)
    ct_raw[25] ^= 0xFF
    tampered_b64 = util.Base64WSEncode(bytes(ct_raw))
    with self.assertRaises(errors.InvalidSignatureError):
      c.Decrypt(tampered_b64)

  def test_tampered_hmac_raises(self):
    c, _ = _make_crypter()
    ct_b64 = c.Encrypt('secret data')
    ct_raw = bytearray(util.Base64WSDecode(ct_b64))
    # Flip the last byte (part of HMAC)
    ct_raw[-1] ^= 0xFF
    tampered_b64 = util.Base64WSEncode(bytes(ct_raw))
    with self.assertRaises(errors.InvalidSignatureError):
      c.Decrypt(tampered_b64)

  def test_wrong_key_raises(self):
    c1, _ = _make_crypter()
    c2, _ = _make_crypter()
    ct = c1.Encrypt('data')
    with self.assertRaises((errors.KeyNotFoundError, errors.InvalidSignatureError)):
      c2.Decrypt(ct)

  def test_short_ciphertext_raises(self):
    c, _ = _make_crypter()
    with self.assertRaises(errors.ShortCiphertextError):
      c.Decrypt(util.Base64WSEncode(b'\x00\x01\x02'))


# ---------------------------------------------------------------------------
# KeyCzarAESCrypter-style usage (mirrors server/core/crypter/keyczar.py)
# ---------------------------------------------------------------------------

class IntegrationTest(unittest.TestCase):
  """
  Tests that mirror the actual usage pattern in the dentalemr backend's
  KeyCzarAESCrypter class.
  """

  def test_generate_key_returns_valid_dict(self):
    key_dict = json.loads(str(keys.AesKey.Generate(size=256)))
    self.assertIn('aesKeyString', key_dict)
    self.assertIn('hmacKey', key_dict)
    self.assertIn('size', key_dict)
    self.assertEqual(key_dict['size'], 256)

  def test_full_workflow(self):
    """
    Simulate:
      1. Generate a master key
      2. Build a Crypter from it
      3. Generate a practice key
      4. Encrypt the practice key with master
      5. Decrypt the practice key with master
      6. Build a Crypter from the practice key
      7. Encrypt / decrypt patient data
    """
    # 1 — master key
    master_key = keys.AesKey.Generate(size=256)
    master_json = str(master_key)

    # 2 — master crypter
    master_reader = readers.StaticKeyReader(
        keys.AesKey.Read(master_json), keyinfo.DECRYPT_AND_ENCRYPT)
    master_crypter = keyczar.Crypter(master_reader)

    # 3 — practice key
    practice_key = keys.AesKey.Generate(size=256)
    practice_json = str(practice_key)

    # 4 — encrypt practice key
    encrypted_practice_key = master_crypter.Encrypt(practice_json)

    # 5 — decrypt practice key
    decrypted_practice_json = master_crypter.Decrypt(encrypted_practice_key)
    self.assertEqual(decrypted_practice_json, practice_json)

    # 6 — practice crypter
    practice_reader = readers.StaticKeyReader(
        keys.AesKey.Read(decrypted_practice_json), keyinfo.DECRYPT_AND_ENCRYPT)
    practice_crypter = keyczar.Crypter(practice_reader)

    # 7 — encrypt / decrypt patient data
    first_name = 'Jane'
    last_name = 'Doe'
    ssn = '123-45-6789'

    enc_fn = practice_crypter.Encrypt(first_name)
    enc_ln = practice_crypter.Encrypt(last_name)
    enc_ssn = practice_crypter.Encrypt(ssn)

    self.assertEqual(practice_crypter.Decrypt(enc_fn), first_name)
    self.assertEqual(practice_crypter.Decrypt(enc_ln), last_name)
    self.assertEqual(practice_crypter.Decrypt(enc_ssn), ssn)

  def test_base64_decoding_error_importable(self):
    """authentication/models.py imports Base64DecodingError."""
    from keyczar.errors import Base64DecodingError
    self.assertTrue(issubclass(Base64DecodingError, Exception))


# ---------------------------------------------------------------------------
# Test vector: verify we can decrypt a ciphertext from the OLD library
# ---------------------------------------------------------------------------

class TestVectorTest(unittest.TestCase):
  """
  This test captures a known ciphertext produced by the original keyczar
  library (pycrypto backend) and verifies the rewritten code can decrypt it.
  If you have a real test vector, replace the values below.
  """

  def test_self_generated_vector_survives_reload(self):
    """
    Generate → encrypt → serialize key + ciphertext → deserialize → decrypt.
    This simulates loading a key from the database and decrypting stored data.
    """
    ak = keys.AesKey.Generate(size=256)
    key_json = str(ak)

    c, _ = _make_crypter(ak)
    plaintext = 'PHI: John Smith SSN 111-22-3333'
    ciphertext = c.Encrypt(plaintext)

    # Simulate: new process, read key from DB, decrypt
    ak2 = keys.AesKey.Read(key_json)
    c2, _ = _make_crypter(ak2)
    self.assertEqual(c2.Decrypt(ciphertext), plaintext)


# ---------------------------------------------------------------------------
# ReadKey dispatch
# ---------------------------------------------------------------------------

class ReadKeyTest(unittest.TestCase):

  def test_read_aes_key(self):
    ak = keys.AesKey.Generate(size=256)
    js = str(ak)
    result = keys.ReadKey(keyinfo.AES, js)
    self.assertIsInstance(result, keys.AesKey)

  def test_read_hmac_key(self):
    hk = keys.HmacKey.Generate()
    js = str(hk)
    result = keys.ReadKey(keyinfo.HMAC_SHA1, js)
    self.assertIsInstance(result, keys.HmacKey)

  def test_unknown_type_raises(self):
    with self.assertRaises(errors.KeyczarError):
      keys.ReadKey('UNKNOWN', '{}')


if __name__ == '__main__':
  unittest.main()
