import json

from flask import Flask, render_template
from ecies.utils import generate_key

from lookup_manager import lookup


def get_keys():
    secp_k = generate_key()
    prvkey_hex = secp_k.to_hex()
    pubkey_hex = secp_k.public_key.format(True).hex()
    return prvkey_hex, pubkey_hex


app = Flask(__name__)
prvkey, pubkey = get_keys()
machine_identifers = {}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/lookup_machines', methods=['GET'])
def get_machine_identifer():
    global pubkey, prvkey
    lookup_results = lookup(pubkey, prvkey)
    return json.dumps(lookup_results)
