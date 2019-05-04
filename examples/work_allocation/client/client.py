from flask import Flask, request, abort, jsonify
from ecdh import DiffieHellman, load_pem_pubkey


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


@app.route('/assign_id', methods=['POST'])
def assign_id():
    server_pubkey = request.data.decode()
    if not server_pubkey:
        abort(400)
    return ''
