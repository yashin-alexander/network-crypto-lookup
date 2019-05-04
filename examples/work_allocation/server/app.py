import json

from flask import Flask, render_template
from ecdh import DiffieHellman

from exchange_manager import process_keys_exchange


app = Flask(__name__)
ecdh = DiffieHellman()
workers_pubkeys = {}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/keys_exchange', methods=['GET'])
def get_machine_identifer():
    global ecdh
    exchange_results = process_keys_exchange(ecdh.pem_pubkey)
    return json.dumps({'devices': list(exchange_results.keys())})
