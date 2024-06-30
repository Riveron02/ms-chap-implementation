from pyrad.client import client
from pyrad.dictionary import dictionary
from pyrad.packet import AccessRequest
import hashlib

radius_client = client(server = '127.0.0.1', secret = b'252729', dict = dictionary("dictionary"))


#function to calculate the response from ms-chap
def chap_challenge_response(username, password):
    challenge = b'\x01\x02\x03\x04\x05\x06\x07\x08'
    challenge_hash = hashlib.new('md5', password.encode('utf-16le')).digest()
    response = hashlib.new('sha256', challenge + challenge_hash).digest()
    return response

def send_radius_request(username, password):
    req = radius_client.CreateAuthPacket(code =AccessRequest, user_name = username)
    response = chap_challenge_response(username, password)

    req['CHAP-Challenge'] = b'\x01\x02\x03\x04\x05\x06\x07\x08'
    req['CHAP-Password'] = response

    reply = radius_client.SendPacket(req)

    if reply.code == 2:
        print("¡Acceso permitido!, bienvenido")
    else:
        print("No es posible acceder.")


