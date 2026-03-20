"""Tests for the RAVEN Payload Encoders module."""

from __future__ import annotations

import pytest

from raven.exploitation.encoders import (
    EncodedPayload,
    alphanum_encode,
    eliminate_nulls,
    find_bad_chars,
    has_bad_chars,
    is_alphanumeric,
    xor_encode,
    xor_encode_multi,
)


class TestEncodedPayload:
    """Tests for the EncodedPayload dataclass."""

    def test_creation(self) -> None:
        ep = EncodedPayload(
            encoded_bytes=b"\x01\x02\x03",
            encoder_name="test",
            original_size=3,
        )
        assert ep.encoded_size == 3  # auto-computed
        assert ep.encoder_name == "test"

    def test_auto_size(self) -> None:
        ep = EncodedPayload(encoded_bytes=b"ABCDE")
        assert ep.encoded_size == 5

    def test_explicit_size_preserved(self) -> None:
        ep = EncodedPayload(encoded_bytes=b"ABC", encoded_size=10)
        assert ep.encoded_size == 10

    def test_to_dict(self) -> None:
        ep = EncodedPayload(
            encoded_bytes=b"\xAB\xCD",
            encoder_name="xor_x86_64",
            original_size=2,
            key=b"\x42",
            bad_chars_avoided=[0x00],
        )
        d = ep.to_dict()
        assert d["encoder_name"] == "xor_x86_64"
        assert d["original_size"] == 2
        assert d["key"] == "42"
        assert d["hex"] == "abcd"
        assert "0x0" in d["bad_chars_avoided"]


class TestXorEncode:
    """Tests for single-byte XOR encoding."""

    def test_basic_encode(self) -> None:
        shellcode = b"\x48\x31\xf6\x56"
        result = xor_encode(shellcode, arch="x86_64")
        assert isinstance(result, EncodedPayload)
        assert result.encoded_size > len(shellcode)  # stub + encoded
        assert result.original_size == len(shellcode)
        assert len(result.key) == 1

    def test_specific_key(self) -> None:
        shellcode = b"\x48\x31\xf6\x56"
        result = xor_encode(shellcode, key=0x42, arch="x86_64")
        assert result.key == b"\x42"
        # Verify the encoded shellcode is actually XOR'd
        for i, b in enumerate(shellcode):
            assert result.encoded_shellcode[i] == b ^ 0x42

    def test_decode_roundtrip(self) -> None:
        """Verify XOR encoding is reversible."""
        shellcode = b"\x48\x31\xf6\x56\x48\xbf"
        result = xor_encode(shellcode, key=0x42, arch="x86_64")
        # XOR the encoded shellcode back
        key_byte = result.key[0]
        decoded = bytes(b ^ key_byte for b in result.encoded_shellcode)
        assert decoded == shellcode

    def test_no_null_bytes_in_output(self) -> None:
        shellcode = b"\x48\x31\xf6\x56"
        result = xor_encode(shellcode, bad_chars={0x00})
        # No null bytes in encoded shellcode
        assert b"\x00" not in result.encoded_shellcode

    def test_custom_bad_chars(self) -> None:
        shellcode = b"\x48\x31\xf6\x56"
        bad_chars = {0x00, 0x0A, 0x0D, 0x20}
        result = xor_encode(shellcode, bad_chars=bad_chars)
        # Encoded shellcode should not contain any bad characters
        for b in result.encoded_shellcode:
            assert b not in bad_chars

    def test_x86_arch_produces_stub(self) -> None:
        shellcode = b"\x31\xc9\xf7\xe1"
        result = xor_encode(shellcode, arch="x86")
        assert len(result.decoder_stub) > 0
        assert "xor_x86" in result.encoder_name

    def test_unsupported_arch_no_stub(self) -> None:
        shellcode = b"\x01\x02\x03\x04"
        result = xor_encode(shellcode, arch="arm64")
        assert result.decoder_stub == b""
        assert result.encoded_size == len(shellcode)

    def test_impossible_key_raises(self) -> None:
        # All possible XOR outputs contain a bad character
        # This is very hard to construct for real shellcode, but we can test the concept
        # by using all 256 values as bad chars except the key
        # Actually, if ALL 256 values are bad, no key works
        bad_chars = set(range(256))
        with pytest.raises(ValueError, match="Cannot find"):
            xor_encode(b"\x00", bad_chars=bad_chars)


class TestXorEncodeMulti:
    """Tests for multi-byte XOR encoding."""

    def test_basic_multi_encode(self) -> None:
        shellcode = b"\x48\x31\xf6\x56\x48\xbf"
        key = b"\xDE\xAD"
        result = xor_encode_multi(shellcode, key)
        assert result.original_size == len(shellcode)
        assert result.encoded_size == len(shellcode)
        assert result.key == key

    def test_multi_roundtrip(self) -> None:
        shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62"
        key = b"\xDE\xAD\xBE\xEF"
        result = xor_encode_multi(shellcode, key)
        # Decode
        key_len = len(key)
        decoded = bytes(result.encoded_shellcode[i] ^ key[i % key_len]
                        for i in range(len(result.encoded_shellcode)))
        assert decoded == shellcode

    def test_empty_key_raises(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            xor_encode_multi(b"\x48\x31", key=b"")

    def test_encoder_name_reflects_key_length(self) -> None:
        result = xor_encode_multi(b"\x48\x31", key=b"\xAB\xCD\xEF")
        assert "3byte" in result.encoder_name


class TestEliminateNulls:
    """Tests for null byte elimination."""

    def test_already_null_free(self) -> None:
        shellcode = b"\x48\x31\xf6\x56"
        result = eliminate_nulls(shellcode)
        assert result.encoded_bytes == shellcode
        assert "none" in result.encoder_name

    def test_removes_nulls(self) -> None:
        shellcode = b"\x48\x00\xf6\x00"
        result = eliminate_nulls(shellcode)
        assert b"\x00" not in result.encoded_shellcode
        assert result.original_size == len(shellcode)

    def test_preserves_original(self) -> None:
        shellcode = b"\x48\x00\xf6\x00"
        result = eliminate_nulls(shellcode)
        # XOR decode should give back original
        key = result.key[0]
        decoded = bytes(b ^ key for b in result.encoded_shellcode)
        assert decoded == shellcode


class TestAlphanumEncode:
    """Tests for alphanumeric encoding."""

    def test_output_is_alphanumeric(self) -> None:
        shellcode = b"\x48\x31\xf6\x00\xff"
        result = alphanum_encode(shellcode)
        assert is_alphanumeric(result.encoded_bytes)

    def test_output_size(self) -> None:
        shellcode = b"\x48\x31\xf6\x56"
        result = alphanum_encode(shellcode)
        # Each byte maps to 2 chars
        assert result.encoded_size == len(shellcode) * 2

    def test_encoding_scheme(self) -> None:
        # Byte 0xAB -> high nibble A (10) -> 0x41+10=0x4B='K'
        #              low nibble B (11) -> 0x41+11=0x4C='L'
        result = alphanum_encode(b"\xAB")
        assert result.encoded_bytes == bytes([0x4B, 0x4C])

    def test_encoder_name(self) -> None:
        result = alphanum_encode(b"\x00")
        assert result.encoder_name == "alphanumeric_basic"


class TestBadCharUtils:
    """Tests for bad character utility functions."""

    def test_has_bad_chars_true(self) -> None:
        data = b"\x48\x00\xf6\x0a"
        assert has_bad_chars(data, {0x00}) is True
        assert has_bad_chars(data, {0x0A}) is True

    def test_has_bad_chars_false(self) -> None:
        data = b"\x48\x31\xf6\x56"
        assert has_bad_chars(data, {0x00}) is False
        assert has_bad_chars(data, {0x0A, 0x0D}) is False

    def test_has_bad_chars_empty_data(self) -> None:
        assert has_bad_chars(b"", {0x00}) is False

    def test_find_bad_chars(self) -> None:
        data = b"\x48\x00\xf6\x00\x0a"
        result = find_bad_chars(data, {0x00, 0x0A})
        offsets = [r[0] for r in result]
        values = [r[1] for r in result]
        assert 1 in offsets  # first null at offset 1
        assert 3 in offsets  # second null at offset 3
        assert 4 in offsets  # 0x0a at offset 4
        assert 0x00 in values
        assert 0x0A in values

    def test_find_bad_chars_none_found(self) -> None:
        data = b"\x48\x31\xf6"
        result = find_bad_chars(data, {0x00})
        assert result == []


class TestIsAlphanumeric:
    """Tests for the is_alphanumeric helper."""

    def test_alphanumeric_true(self) -> None:
        assert is_alphanumeric(b"ABCabc012") is True

    def test_alphanumeric_false(self) -> None:
        assert is_alphanumeric(b"ABC\x00") is False
        assert is_alphanumeric(b"hello world") is False  # space is not alphanum

    def test_alphanumeric_empty(self) -> None:
        assert is_alphanumeric(b"") is True
