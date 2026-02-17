import unittest

from saga_protocol import (
    FrameTooLarge,
    decode_frame_from_bytes,
    encode_frame,
    sign_message,
    verify_message,
)


class TestFraming(unittest.TestCase):
    def test_frame_roundtrip(self) -> None:
        msg = {"type": "status", "timestamp": 123.0, "payload": {"ok": True}}
        data = encode_frame(msg)
        decoded, rest = decode_frame_from_bytes(data)
        self.assertEqual(decoded, msg)
        self.assertEqual(rest, b"")

    def test_multiple_frames(self) -> None:
        a = encode_frame({"a": 1})
        b = encode_frame({"b": 2})
        decoded1, rest = decode_frame_from_bytes(a + b)
        decoded2, rest2 = decode_frame_from_bytes(rest)
        self.assertEqual(decoded1, {"a": 1})
        self.assertEqual(decoded2, {"b": 2})
        self.assertEqual(rest2, b"")

    def test_frame_too_large(self) -> None:
        msg = {"x": "a" * 100}
        with self.assertRaises(FrameTooLarge):
            encode_frame(msg, max_frame_bytes=10)


class TestAuth(unittest.TestCase):
    def test_sign_and_verify(self) -> None:
        token = "secret"
        msg = {"type": "location", "timestamp": 1.0, "payload": {"description": "here"}}
        signed = sign_message(msg, token, ts=1700000000, nonce="abc")
        self.assertTrue(verify_message(signed, token, max_skew_s=None))

        tampered = dict(signed)
        tampered["payload"] = {"description": "there"}
        self.assertFalse(verify_message(tampered, token, max_skew_s=None))

    def test_verify_requires_auth(self) -> None:
        token = "secret"
        msg = {"type": "status", "timestamp": 1.0, "payload": {"code": "1"}}
        self.assertFalse(verify_message(msg, token, max_skew_s=None))


if __name__ == "__main__":
    unittest.main()