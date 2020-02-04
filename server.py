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

    def lineReceived(self, line):
        print(line)
        try:
            data = self.packet.parse(line + b'\r\n')
            print(data)
            print(data.protocol)
            if str(data.protocol) == 'login':
                self.handleLogin(data)
            else:
                self.handleUnknown(data)
        except Exception as e:
            print(e)
            pass

    def handleLogin(self, data):
        print("login from %s (%s)" % (data.data.imei, data.data.model))

        now = datetime.now(timezone.utc)
        year = int(now.strftime("%y"))
        dt = dict(year=year, month=now.month, day=now.day, hour=now.hour, minute=now.minute, second=now.second)
        respdata = Packet.login_response.build(dict(datetime=dt, reserved_length=0, reserved=0))
        serial = data.serial + 1
        resp = self.packet.build(dict(start=b"\x78\x78", fields=dict(value=dict(length=1+(6+1+0)+2+2, protocol=0x01, data=respdata, serial=serial))))
        self.transport.write(resp)

    def handleUnknown(self, data):
        print("Got unkown packet, protocol is %d" % (data.protocol,))

class BL10Factory(protocol.Factory):
    def buildProtocol(self, addr):
        return BL10()

endpoint = endpoints.TCP4ServerEndpoint(reactor, PORT, interface=HOST)
endpoint.listen(BL10Factory())
reactor.run()