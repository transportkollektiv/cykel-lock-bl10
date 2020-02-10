import unittest
from crccheck.crc import CrcX25

class Crc16TestCase(unittest.TestCase):

    def test_crc16(self):
        data = b'\x05\x01\x00\x03'
        self.assertEqual(CrcX25.calc(data), 0xface)

    def test_login_packet_with_weird_secret(self):
        # 11 01 08 68 12 01 48 37 35 71 36 05 32 02 00 39 # DE F7
        packet = b'\x11\x01\x08\x68\x12\x01\x48\x37\x35\x71\x36\x05\x32\x02\x00\x39'
        secret = b'xinsiwei&concox'
        packet = packet + secret
        self.assertEqual(CrcX25.calc(packet), 57079)

    def test_login_response_packet(self):
        # 0C 01 11 03 14 08 38 39 00 00 39 # 95 70
        packet = b'\x0C\x01\x11\x03\x14\x08\x38\x39\x00\x00\x39' # \x95\x70
        self.assertEqual(CrcX25.calc(packet), 38256)
