from flask import Flask, request, abort, jsonify
import json
import time
import threading
from ecdh import DiffieHellman, load_pem_pubkey, from_base64_dict, to_base64_dict


app = Flask(__name__)
ecdh = DiffieHellman()
server_pubkey = None
work_processing = False


@app.route('/assign_server_pubkey', methods=['POST'])
def assign_server_pubkey():
    global ecdh, server_pubkey
    try:
        server_pubkey = load_pem_pubkey(request.data)
    except (TypeError, ValueError):
        abort(400)
    payload = {'pubkey': ecdh.pem_pubkey}
    return jsonify(payload), 200


@app.route('/device_state', methods=['GET'])
def device_state():
    global ecdh, server_pubkey, work_processing
    if not server_pubkey:
        abort(400)
    encrypted_message = ecdh.encrypt(server_pubkey, str(work_processing))
    raw_dict = {'iv': ecdh.IV, 'payload': encrypted_message}
    payload = to_base64_dict(raw_dict)
    return jsonify(payload), 200


@app.route('/process_work', methods=['POST'])
def process_work():
    global ecdh, server_pubkey, work_processing
    encoded_dict = json.loads(request.data)
    decoded_dict = from_base64_dict(encoded_dict)
    try:
        work_delay = ecdh.decrypt(server_pubkey,
                                  decoded_dict.get('payload'),
                                  decoded_dict.get('iv'))
    except TypeError:
        abort(400)
    if work_processing:
        abort(400)
    worker = threading.Thread(target=_work, args=(int(work_delay), ))
    worker.start()
    return '', 200


def _work(delay):
    global work_processing
    work_processing = True
    time.sleep(delay)
    work_processing = False
