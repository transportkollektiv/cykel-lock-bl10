import os
from datetime import datetime, timezone
from twisted.internet import protocol, reactor, endpoints
from twisted.protocols.basic import LineReceiver
from packet import Packet

HOST = os.environ.get('HOST', '127.0.0.1')
PORT = int(os.environ.get('PORT', '21105'))

class BL10(LineReceiver):
    def __init__(self):
        self.packet = Packet()

    def printPacket(self, direction, packet):
        dt = datetime.utcnow().replace(tzinfo=timezone.utc).astimezone().replace(microsecond=0).isoformat()
        if direction == '>':
            direction = '==>'
        else: 
            direction = '<=='
        print("%s %s %s" % (dt, direction, binascii.hexlify(packet), ))

    def lineReceived(self, line):
        self.printPacket("<", line)
        try:
            data = self.packet.parse(line + b'\r\n')
            print(data)
            print(data.protocol)
            if str(data.protocol) == 'login':
                self.handleLogin(data)
            elif str(data.protocol) == 'heartbeat':
                self.handleHeartbeat(data)
            elif str(data.protocol) == 'location':
                self.handleLocation(data)
            elif str(data.protocol) == 'alarm':
                self.handleAlarm(data)
            elif str(data.protocol) == 'information':
                self.handleInformation(data)
            else:
                self.handleUnknown(data)
        except Exception as e:
            print(e)
            pass

    def write(self, data):
        self.printPacket(">", data)
        self.transport.write(data)

    def handleLogin(self, data):
        print("login from %s (%s)" % (data.data.imei, data.data.model))

        now = datetime.now(timezone.utc)
        year = int(now.strftime("%y"))
        dt = dict(year=year, month=now.month, day=now.day, hour=now.hour, minute=now.minute, second=now.second)
        respdata = Packet.login_response.build(dict(datetime=dt, reserved_length=0, reserved=0))
        serial = data.serial + 1
        resp = self.packet.build(dict(start=b"\x78\x78", fields=dict(value=dict(length=1+(6+1+0)+2+2, protocol=0x01, data=respdata, serial=serial))))
        self.write(resp)

    def handleHeartbeat(self, data):
        serial = data.serial + 1
        resp = self.packet.build(dict(start=b"\x78\x78", fields=dict(value=dict(length=1+2+2, protocol=0x23, data=bytes(), serial=serial))))
        self.write(resp)

    def handleLocation(self, data):
        serial = data.serial + 1
        resp = self.packet.build(dict(start=b"\x79\x79", fields=dict(value=dict(length=1+2+2, protocol=0x32, data=bytes(), serial=serial))))
        self.write(resp)

    def handleAlarm(self, data):
        serial = data.serial + 1
        resp = self.packet.build(dict(start=b"\x79\x79", fields=dict(value=dict(length=1+2+2, protocol=0x33, data=bytes(), serial=serial))))
        self.write(resp)

    def handleInformation(self, data):
        serial = data.serial + 1
        resp = self.packet.build(dict(start=b"\x79\x79", fields=dict(value=dict(length=1+(1)+2+2, protocol=0x98, data=bytes(1), serial=serial))))
        self.write(resp)

    def handleUnknown(self, data):
        print("Got unkown packet, protocol is %d" % (data.protocol,))

class BL10Factory(protocol.Factory):
    def buildProtocol(self, addr):
        return BL10()

endpoint = endpoints.TCP4ServerEndpoint(reactor, PORT, interface=HOST)
endpoint.listen(BL10Factory())
reactor.run()