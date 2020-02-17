import os
import binascii
import requests
import jsons
from datetime import datetime, timezone
from twisted.internet import protocol, reactor, endpoints
from twisted.protocols.basic import LineReceiver
from twisted.web.server import Site
from klein import Klein
from packet import Packet

HOST = os.environ.get('HOST', '127.0.0.1')
PORT = int(os.environ.get('PORT', '8000'))
LOCK_PORT = int(os.environ.get('LOCK_PORT', '21105'))
ENDPOINT = os.environ['ENDPOINT']
ENDPOINT_AUTH_HEADER = os.getenv('ENDPOINT_AUTH_HEADER', '')

headers = {
    'Content-Type': 'application/json'
}
if ENDPOINT_AUTH_HEADER is not '':
    headers['Authorization'] = ENDPOINT_AUTH_HEADER

class BL10(LineReceiver):
    device_id = None
    serial = 0

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
            proto = str(data.protocol)
            print(proto)
            self.serial = data.serial
            if proto == 'login':
                self.handleLogin(data)
            elif proto == 'heartbeat':
                self.handleHeartbeat(data)
            elif proto == 'location':
                self.handleLocation(data)
            elif proto == 'alarm':
                self.handleAlarm(data)
            elif proto == 'information':
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
        self.serial += 1
        resp = self.packet.build(dict(start=b"\x78\x78", fields=dict(value=dict(length=1+(6+1+0)+2+2, protocol=0x01, data=respdata, serial=self.serial))))
        self.write(resp)

        self.device_id = str(data.data.imei)

        update = {
            'device_id': self.device_id
        }
        print(jsons.dumps(update))
        resp = requests.post(ENDPOINT, headers=headers, data=jsons.dumps(update))
        print(resp)

    def handleHeartbeat(self, data):
        self.serial += 1
        resp = self.packet.build(dict(start=b"\x78\x78", fields=dict(value=dict(length=1+2+2, protocol=0x23, data=bytes(), serial=self.serial))))
        self.write(resp)

        update = {
            'device_id': self.device_id,
            'battery_voltage': data.data.voltage
        }
        print(jsons.dumps(update))
        resp = requests.post(ENDPOINT, headers=headers, data=jsons.dumps(update))
        print(resp)

    def handleLocation(self, data):
        self.serial += 1
        resp = self.packet.build(dict(start=b"\x79\x79", fields=dict(value=dict(length=1+2+2, protocol=0x32, data=bytes(), serial=self.serial))))
        self.write(resp)

        update = {
            'device_id': self.device_id
        }
        
        if data.data.gps:
            # FIXME: something something with the data.data.gps.cs.latitude, data.data.gps.cs.longitude flags
            update['lat'] = data.data.gps.latitude
            update['lng'] = data.data.gps.longitude

        print(jsons.dumps(update))
        resp = requests.post(ENDPOINT, headers=headers, data=jsons.dumps(update))
        print(resp)

    def handleAlarm(self, data):
        self.serial += 1
        resp = self.packet.build(dict(start=b"\x79\x79", fields=dict(value=dict(length=1+2+2, protocol=0x33, data=bytes(), serial=self.serial))))
        self.write(resp)

    def handleInformation(self, data):
        self.serial += 1
        resp = self.packet.build(dict(start=b"\x79\x79", fields=dict(value=dict(length=1+(1)+2+2, protocol=0x98, data=bytes(1), serial=self.serial))))
        self.write(resp)

    def handleUnknown(self, data):
        self.serial += 1
        print("Got unkown packet, protocol is %d" % (data.protocol,))

class BL10Factory(protocol.Factory):
    def buildProtocol(self, addr):
        return BL10()

http = Klein()

class NotFound(Exception):
    pass

@http.handle_errors(NotFound)
def not_found(request, failure):
    request.setResponseCode(404)
    return 'Not found'

@http.route('/')
def home(request):
    return 'Hello, world!'

bl10endpoint = endpoints.TCP4ServerEndpoint(reactor, LOCK_PORT, interface=HOST)
bl10endpoint.listen(BL10Factory())

httpendpoint = endpoints.TCP4ServerEndpoint(reactor, PORT, interface=HOST)
httpendpoint.listen(Site(http.resource()))
reactor.run()