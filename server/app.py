import requests
import json

from flask import Flask, render_template
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


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/lookup_ips')
def lookup_ips():
    network_ips = lookup()
    return "Some ip's detected: {}".format(network_ips)


def get_machine_identifer(ip):
    global prvkey, pubkey
    url = 'http://{}:{}/encrypted_identifer'.format(ip, CLIENT_APP_PORT)
    try:
        response = requests.post(url,
                                 data=pubkey.encode(),
                                 headers={'Content-Type': 'application/octet-stream'},
                                 timeout=5)
    except requests.exceptions.ConnectionError:
        return None
    if not response.ok:
        return None
    encrypted_machine_identifer = response.content
    machine_identifer = decrypt(prvkey, encrypted_machine_identifer)
    return machine_identifer


@app.route('/lookup_machines', methods=['GET'])
def lookup_machines():
    network_ips = lookup()
    machine_identifers = {}
    print("Networks detected: {}".format(network_ips))
    for ip in network_ips:
        machine_identifer = get_machine_identifer(ip)
        if not machine_identifer:
            print('Failed to connect to {}'.format(ip))
            continue
        print('{} connection successfull'.format(ip))
        decoded_identifer = machine_identifer.decode()
        machine_identifers.update({ip: decoded_identifer})
    return json.dumps(machine_identifers)
