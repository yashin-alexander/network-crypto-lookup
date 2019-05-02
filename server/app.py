import requests
from flask import Flask
from ecies.utils import generate_key
from ecies import decrypt
from lookup_manager import lookup


CLIENT_APP_PORT = 5000


def get_keys():
    secp_k = generate_key()
    prvkey_hex = secp_k.to_hex()
    pubkey_hex = secp_k.public_key.format(True).hex()
    return prvkey_hex, pubkey_hex


app = Flask(__name__)
prvkey, pubkey = get_keys()
network_ips = []
machine_identifers = {}


def lookup_ips():
    network_ips = lookup()
    return "Some ip's detected: {}".format(network_ips)


def get_machine_identifer(ip):
    global prvkey, pubkey
    ip = '0.0.0.0'
    url = 'http://{}:{}/encrypted_identifer'.format(ip, CLIENT_APP_PORT)
    response = requests.post(url,
                             data=pubkey.encode(),
                             headers={'Content-Type': 'application/octet-stream'})
    if not response.ok:
        return None
    encrypted_machine_identifer = response.content
    machine_identifer = decrypt(prvkey, encrypted_machine_identifer)
    return machine_identifer


@app.route('/lookup_machines')
def lookup_machines():
    network_ips = lookup()
    machine_identifers = {}
    for ip in network_ips:
        machine_identifer = get_machine_identifer(ip)
        if machine_identifer:
            machine_identifers.update({ip: machine_identifer})
    return str(machine_identifers)
