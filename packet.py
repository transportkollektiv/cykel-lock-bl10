from crccheck.crc import CrcX25
from construct import *
from construct.lib import *
import binascii

CRC_SECRET = b'xinsiwei&concox'

class HexString(Hex):
    def _decode(self, obj, context, path):
        if isinstance(obj, bytes):
            return HexDisplayedString(obj)
        return super._decode(obj, context, path)

class HexDisplayedString(bytes):
    def __str__(self):
        return binascii.hexlify(self).decode('ascii')

    def __repr__(self):
        return self.__str__()

class Packet:
    login = Struct(
        "imei" / HexString(Bytes(8)),
        "model" / HexString(Bytes(2)),
        "tzlg" / BitStruct(
            "tz" / BitsInteger(12),
            "gmt" / Enum(Bit, eastern=0, western=1),
            Padding(1),
            "lang" / BitsInteger(2)
        )
    )

    datetime = Struct(
        "year" / Byte,
        "month" / Byte,
        "day" / Byte,
        "hour" / Byte,
        "minute" / Byte,
        "second" / Byte
    )

    login_response = Struct(
        "datetime" / datetime,
        "reserved_length" / Byte, #Rebuild(Byte, len_(this.reserved)),
        "reserved" / If(this.reserved_length == 1, Byte)
    )

    heartbeat = Struct(
        "tic" / BitStruct(
            Padding(1),
            "gps" / Flag,
            Padding(3),
            "charge" / Flag,
            Padding(1),
            "locked" / Flag
        ),
        "voltage" / ExprAdapter(Int16ub,
            encoder = lambda obj, ctx: obj * 100,
            decoder = lambda obj, ctx: obj / 100,
        ),
        "signal" / Enum(Byte, none=0x00, extemely_weak=0x01, weak=0x02, good=0x03, strong=0x04),
        "extportstatus" / Byte,
        "language" / Enum(Byte, chinese=0x01, english=0x02)
    )

    command = Struct(
        "length" / Byte,
        "serverflag" / Bytes(4),
        "content" / GreedyBytes #Bytes(this._.length - 1 - 4),
        #"language" / Enum(Bytes(2), chinese=0x01, english=0x02) # FIXME ?! (documented in manual, not there in manual example)
    )

    response = Struct(
        "serverflag" / Bytes(4),
        "encoding" / Enum(Byte, ascii=0x01, utf16be=0x02),
        "content" / Bytes(this._.length - 1 - 4 - 1 - 2 - 2)
    )

    gps = Struct(
        "gps_satellites" / Byte,
        "latitude" / ExprAdapter(Int32ub,
            encoder = lambda obj, ctx: obj * 1800000,
            decoder = lambda obj, ctx: obj / 1800000,
        ),
        "longitude" / ExprAdapter(Int32ub,
            encoder = lambda obj, ctx: obj * 1800000,
            decoder = lambda obj, ctx: obj / 1800000,
        ),
        "speed" / Byte,
        "cs" / BitStruct(
            Padding(2),
            "gps_rtdp" / Enum(Bit, realtime=0, differential=1),
            "positioning" / Flag,
            "longitude" / Enum(Bit, east=0, west=1),
            "latitude" / Enum(Bit, south=0, north=1),
            "course" / BitsInteger(10)
        )
    )

    main_lbs = Struct(
        "mcc" / Bytes(2),
        "mnc" / Byte,
        "lac" / Bytes(2),
        "ci" / Bytes(3),
        "rssi" / Byte,
    )

    lbs = Struct(
        "lac" / Bytes(2),
        "ci" / Bytes(3),
        "rssi" / Byte,
    )

    wifi = Struct(
        "mac" / Bytes(6),
        "strength" / Byte,
    )

    reserved = Struct(
        "bluetoothflag" / Bytes(2),
        "reupload" / Flag
    )

    location = Struct(
        "datetime" / datetime,
        "gps_length" / Byte,
        "gps" / If(this.gps_length == 12, gps),
        "main_lbs_length" / Byte,
        "main_lbs" / If(this.main_lbs_length == 9, main_lbs),
        "lbs_sub_length" / Byte,
        "lbs" / Array(lambda ctx: int(int(ctx.lbs_sub_length) / 6), lbs),
        "wifi_length" / Byte,
        "wifi" / Array(lambda ctx: int(int(ctx.wifi_length) / 7), wifi),
        "status" / Byte, # FIXME enum
        "reserved_length" / Byte,
        "reserved" / If(this.reserved_length == 3, reserved)
    )

    info = Struct(
        "type" / Enum(Byte, imei=0x00, imsi=0x01, iccid=0x02, chipid=0x03, bluetoothmac=0x04, unlockkey=0x05, fwversion=0x07, default=Pass),
        "length" / BytesInteger(2),
        "content" / Bytes(this.length)
    )

    information = GreedyRange(info) #RepeatUntil(lambda obj,lst,ctx: something_current_position, (ctx._.length - 1 - 2 - 2), info)

    protocol = Struct(
        "start" / OneOf(Bytes(2), [b"\x78\x78", b"\x79\x79"]),
        "fields" / RawCopy(Struct(
            "length" / IfThenElse(this._.start == b"\x78\x78", Int8ub, Int16ub),
            "protocol" / Enum(Byte, login=0x01, heartbeat=0x23, response=0x21, location=0x32, alarm=0x33, command=0x80, information=0x98, default=Pass),
            "data" / Switch(this.protocol,
                {
                    "login": login,
                    "heartbeat": heartbeat,
                    "response": response,
                    "location": location,
                    "alarm": location,
                    "information": information,
                },
                default=Bytes(this.length - 1 - 2 - 2)
            ),
            "serial" / Int16ub,
        )),
        "crc" / Checksum(BytesInteger(2),
            lambda data: CrcX25.calc(data),
            lambda ctx: ctx.fields.data + CRC_SECRET if ctx.fields.value.protocol == 'login' else ctx.fields.data
        ),
        "end" / Const(b"\x0d\x0a")
    )

    #def __init__(self):
    #    # void

    def parse(self, packet):
        return self.protocol.parse(packet).fields.value

    def build(self, packetdata):
        return self.protocol.build(packetdata)
