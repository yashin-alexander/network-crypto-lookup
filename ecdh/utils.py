import base64


def from_base64_dict(encoded_dict):
    decoded_dict = {}
    for element in encoded_dict:
        value = base64.b64decode(encoded_dict[element].encode())
        decoded_dict.update({element: value})
    return decoded_dict


def to_base64_dict(raw_dict):
    encoded_dict = {}
    for element in raw_dict:
        encoded_dict.update({element: base64.b64encode(raw_dict[element]).decode()})
    return encoded_dict
