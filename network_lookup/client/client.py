from flask import Flask, request, abort
from ecies import encrypt


app = Flask(__name__)
machine_identifer = b'1234567890/TRN.VR-FR-KR'


@app.route('/encrypted_identifer', methods=['POST'])
def encrypted_identifer():
    server_pubkey = request.data.decode()
    if not server_pubkey:
        abort(400)
    encrypted_identifer = encrypt(server_pubkey, machine_identifer)
    return encrypted_identifer
