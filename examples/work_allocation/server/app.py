import json
import requests

from flask import Flask, render_template, jsonify
from ecdh import DiffieHellman, to_base64_dict, from_base64_dict

from exchange_manager import (process_keys_exchange, get_local_network_ip_base,
                              CLIENT_APP_PORT)


app = Flask(__name__)
ecdh = DiffieHellman()
workers_pubkeys = process_keys_exchange(ecdh.pem_pubkey)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/keys_exchange', methods=['GET'])
def get_machine_identifer():
    global ecdh, workers_pubkeys
    workers_pubkeys = process_keys_exchange(ecdh.pem_pubkey)
    return json.dumps({'devices': list(workers_pubkeys.keys())})


@app.route('/devices_states', methods=['GET'])
def get_devices_states():
    global workers_pubkeys
    devices_states = {}
    for worker in workers_pubkeys.keys():
        devices_states.update({worker: _get_device_state(worker)})
    return jsonify(devices_states)


@app.route('/device_state_<id>', methods=['GET'])
def get_device_state(id):
    ip_base = get_local_network_ip_base()
    worker_ip = '{}{}'.format(ip_base, id)
    return _get_device_state(worker_ip)


def _get_device_state(ip):
    global workers_pubkeys
    url = 'http://{}:{}/device_state'.format(ip, CLIENT_APP_PORT)
    response = requests.get(url)
    if not response.ok:
        return 'Unknown'
    encoded_dict = response.json()
    decoded_dict = from_base64_dict(encoded_dict)
    try:
        device_state = ecdh.decrypt(workers_pubkeys.get(ip),
                                    decoded_dict.get('payload'),
                                    decoded_dict.get('iv'))
    except TypeError:
        return 'Unknown'
    return device_state


@app.route('/process_work_<id>', methods=['GET'])
def process_work(id):
    global workers_pubkeys
    ip_base = get_local_network_ip_base()
    worker_ip = '{}{}'.format(ip_base, id)
    url = 'http://{}:{}/process_work'.format(worker_ip, CLIENT_APP_PORT)
    encrypted_message = ecdh.encrypt(workers_pubkeys.get(worker_ip), '10')
    raw_dict = {'iv': ecdh.IV, 'payload': encrypted_message}
    payload = to_base64_dict(raw_dict)
    response = requests.post(url,
                             data=json.dumps(payload),
                             headers={'Content-Type': 'application/octet-stream'},
                             timeout=5)
    if not response.ok:
        return 'Cannot delegate work'
    return 'Work delegated'
