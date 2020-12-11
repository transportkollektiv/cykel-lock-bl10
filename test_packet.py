import unittest
import binascii
from packet import Packet

class PacketTestCase(unittest.TestCase):
    def pparse(self, packet, instance=None):
        pp = instance or Packet()
        parsed = pp.parse(packet)
        #print(binascii.hexlify(packet))
        #print(parsed)
        return parsed

    def test_login_packet(self):
        # 78 78 11 01 03 55 95 10 91 34 92 95 36 08 00 02 00 02 08 97 0d 0a
        packet = b"\x78\x78\x11\x01\x03\x55\x95\x10\x91\x34\x92\x95\x36\x08\x00\x02\x00\x02\x08\x97\x0d\x0a"
        parsed = self.pparse(packet)
        self.assertEqual(parsed.protocol, "login")
        self.assertEqual(binascii.hexlify(parsed.data.imei), b"0355951091349295")
        self.assertEqual(parsed.data.model, b"\x36\x08")

    def test_login_packet_other_secret(self):
        # FIXME: update protocol test with changed key
        # 78 78 11 01 03 55 95 10 91 34 92 95 36 08 00 02 00 02 08 97 0d 0a
        packet = b"\x78\x78\x11\x01\x03\x55\x95\x10\x91\x34\x92\x95\x36\x08\x00\x02\x00\x02\x08\x97\x0d\x0a"
        parsed = self.pparse(packet, Packet(crc_secret='testsecret'))
        self.assertEqual(parsed.protocol, "login")
        self.assertEqual(binascii.hexlify(parsed.data.imei), b"0355951091349295")
        self.assertEqual(parsed.data.model, b"\x36\x08")

    def test_login_manual_packet(self):
        # 78 78 11 01 08 68 12 01 48 37 35 71 36 05 32 02 00 39 DE F7 0D 0A
        packet = b"\x78\x78\x11\x01\x08\x68\x12\x01\x48\x37\x35\x71\x36\x05\x32\x02\x00\x39\xDE\xF7\x0D\x0A"
        parsed = self.pparse(packet)
        self.assertEqual(parsed.protocol, "login")
        self.assertEqual(binascii.hexlify(parsed.data.imei), b"0868120148373571")
        self.assertEqual(parsed.data.model, b"\x36\x05")

    def test_information_packet(self):
        # 79 79 00 80 98 00 00 08 03 55 95 10 91 34 92 95 01 00 08 02 34 50 70 98 64 53 87 02 00 0a 89 44 50 03 07 18 64 53 87 9f 03 00 10 3c 0b f8 cf 8a 97 99 be 38 d5 28 a9 ea 79 1c 04 04 00 06 c4 a8 28 08 2c 40 05 00 06 30 30 30 30 30 30 06 00 10 20 57 2f 52 36 4b 3f 47 30 50 41 58 11 63 2d 2b 07 00 1d 47 42 31 31 30 5f 31 30 5f 41 31 44 45 5f 44 32 33 5f 52 30 5f 56 30 32 5f 57 49 46 49 00 03 07 91 0d 0a
        packet = b"\x79\x79\x00\x80\x98\x00\x00\x08\x03\x55\x95\x10\x91\x34\x92\x95\x01\x00\x08\x02\x34\x50\x70\x98\x64\x53\x87\x02\x00\x0a\x89\x44\x50\x03\x07\x18\x64\x53\x87\x9f\x03\x00\x10\x3c\x0b\xf8\xcf\x8a\x97\x99\xbe\x38\xd5\x28\xa9\xea\x79\x1c\x04\x04\x00\x06\xc4\xa8\x28\x08\x2c\x40\x05\x00\x06\x30\x30\x30\x30\x30\x30\x06\x00\x10\x20\x57\x2f\x52\x36\x4b\x3f\x47\x30\x50\x41\x58\x11\x63\x2d\x2b\x07\x00\x1d\x47\x42\x31\x31\x30\x5f\x31\x30\x5f\x41\x31\x44\x45\x5f\x44\x32\x33\x5f\x52\x30\x5f\x56\x30\x32\x5f\x57\x49\x46\x49\x00\x03\x07\x91\x0d\x0a"
        parsed = self.pparse(packet)
        self.assertEqual(parsed.protocol, "information")

    def test_heartbeat_packet(self):
        # 78 78 0b 23 00 01 66 03 00 01 00 04 5e ac 0d 0a
        packet = b"\x78\x78\x0b\x23\x00\x01\x66\x03\x00\x01\x00\x04\x5e\xac\x0d\x0a"
        parsed = self.pparse(packet)
        self.assertEqual(parsed.protocol, "heartbeat")
        self.assertEqual(parsed.data.tic.locked, False)
        self.assertEqual(parsed.data.voltage, 3.58)
        self.assertEqual(parsed.data.signal, "good")

    def test_heartbeat_manual_packet(self):
        # 78 78 0B 23 C0 01 22 04 00 01 00 08 18 72 0D 0A
        packet = b"\x78\x78\x0B\x23\xC0\x01\x22\x04\x00\x01\x00\x08\x18\x72\x0D\x0A"
        parsed = self.pparse(packet)
        self.assertEqual(parsed.protocol, "heartbeat")

    def test_location_packet(self):
        # 79 79 00 3e 32 14 01 1c 11 29 11 00 09 01 06 02 1c 42 00 6d 3b 19 24 1c 42 00 44 9a 13 1c 42 00 44 99 08 1c 42 00 44 9b 06 1c 42 00 6d 3a 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 84 06 0d 0a
        packet = b'\x79\x79\x00\x3e\x32\x14\x01\x1c\x11\x29\x11\x00\x09\x01\x06\x02\x1c\x42\x00\x6d\x3b\x19\x24\x1c\x42\x00\x44\x9a\x13\x1c\x42\x00\x44\x99\x08\x1c\x42\x00\x44\x9b\x06\x1c\x42\x00\x6d\x3a\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x84\x06\x0d\x0a'
        parsed = self.pparse(packet)
        self.assertEqual(parsed.protocol, "location")
        self.assertEqual(parsed.data.gps_length, 0)
        self.assertEqual(parsed.data.main_lbs_length, 9)

    def test_alarm_manual_packet(self):
        # 79 79 00 6F 33 11 03 14 09 06 08 00 09 01 CC 00 28 7D 00 1F 40 0E 24 28 7D 00 1F 71 07 28 7D 00 1E 3F 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 31 00 36 76 05 BB 5D 46 00 87 36 31 87 5B 48 CC 7B 35 36 61 A6 4C 00 E0 4B 8C BF 58 4F 78 A1 06 54 15 DE 4F 00 87 46 1B 9D 84 51 26 52 F3 AD B1 94 55 A1 00 00 08 38 B2 0D 0A
        packet = b'\x79\x79\x00\x6F\x33\x11\x03\x14\x09\x06\x08\x00\x09\x01\xCC\x00\x28\x7D\x00\x1F\x40\x0E\x24\x28\x7D\x00\x1F\x71\x07\x28\x7D\x00\x1E\x3F\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x31\x00\x36\x76\x05\xBB\x5D\x46\x00\x87\x36\x31\x87\x5B\x48\xCC\x7B\x35\x36\x61\xA6\x4C\x00\xE0\x4B\x8C\xBF\x58\x4F\x78\xA1\x06\x54\x15\xDE\x4F\x00\x87\x46\x1B\x9D\x84\x51\x26\x52\xF3\xAD\xB1\x94\x55\xA1\x00\x00\x08\x38\xB2\x0D\x0A'
        parsed = self.pparse(packet)
        self.assertEqual(parsed.protocol, "alarm")

    def test_response_packet(self):
        # 79 79 00 0D 21 00 00 00 00 01 4F 4B 21 00 07 A6 30 0D 0A
        packet = b'\x79\x79\x00\x0D\x21\x00\x00\x00\x00\x01\x4F\x4B\x21\x00\x07\xA6\x30\x0D\x0A'
        parsed = self.pparse(packet)
        self.assertEqual(parsed.protocol, "response")
        self.assertEqual(parsed.data.serverflag, b"\x00\x00\x00\x00")
        self.assertEqual(parsed.data.encoding, "ascii")
        self.assertEqual(parsed.data.content, b"\x4F\x4B\x21")
        self.assertEqual(parsed.serial, 7)

    def test_login_response_packet(self):
        pp = Packet()
        packet = pp.build(dict(start=b"\x78\x78", fields=dict(value=dict(length=1+(6+1+0)+2+2, protocol=0x01, data=Packet.login_response.build(dict(datetime=dict(year=17, month=3, day=20, hour=8, minute=56, second=57), reserved_length=0, reserved=0)), serial=0x39))))
        self.assertEqual(packet, b'\x78\x78\x0C\x01\x11\x03\x14\x08\x38\x39\x00\x00\x39\x95\x70\x0D\x0A')

    def test_heartbeat_response_packet(self):
        pp = Packet()
        packet = pp.build(dict(start=b"\x78\x78", fields=dict(value=dict(length=1+2+2, protocol=0x23, data=bytes(), serial=256))))
        self.assertEqual(packet, b'\x78\x78\x05\x23\x01\x00\x67\x0E\x0D\x0A')

    def test_location_response_packet(self):
        pp = Packet()
        packet = pp.build(dict(start=b"\x79\x79", fields=dict(value=dict(length=1+2+2, protocol=0x32, data=bytes(), serial=256))))
        self.assertEqual(packet, b'\x79\x79\x00\x05\x32\x01\x00\x8B\xEE\x0D\x0A')

    def test_alarm_response_packet(self):
        pp = Packet()
        packet = pp.build(dict(start=b"\x79\x79", fields=dict(value=dict(length=1+2+2, protocol=0x33, data=bytes(), serial=256))))
        self.assertEqual(packet, b'\x79\x79\x00\x05\x33\x01\x00\xD1\x32\x0D\x0A')

    def test_information_response_packet(self):
        pp = Packet()
        packet = pp.build(dict(start=b"\x79\x79", fields=dict(value=dict(length=1+(1)+2+2, protocol=0x98, data=bytes(1), serial=0))))
        self.assertEqual(packet, b'\x79\x79\x00\x06\x98\x00\x00\x00\xC7\x00\x0D\x0A')

    def test_command_packet(self):
        pp = Packet()
        data = Packet.command.build(dict(length=4+7, serverflag=0, content=b"UNLOCK#"))
        packet = pp.build(dict(start=b"\x78\x78", fields=dict(value=dict(length=1+(1+4+7)+2+2, protocol=0x80, data=data, serial=1))))
        self.assertEqual(packet, b'\x78\x78\x11\x80\x0B\x00\x00\x00\x00\x55\x4E\x4C\x4F\x43\x4B\x23\x00\x01\x53\x54\x0D\x0A')
