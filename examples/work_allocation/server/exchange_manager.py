import multiprocessing
import requests
import socket
import re
from simplejson.errors import JSONDecodeError

from ecdh import load_pem_pubkey


DNS = "8.8.8.8"
DEFAULT_POOL_SIZE = 255
ADDRESSES_RANGE = 255
CLIENT_APP_PORT = 5000


class KeysExchangeManager():
    def __init__(self, pubkey):
        self. worker_devices = {}
        self.pubkey = pubkey

    @property
    def localhost_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((DNS, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip

    @property
    def _local_network_ip_base(self):
        return re.sub('[^.]*$', '', self.localhost_ip)

    def _worker_cb(self, result):
        for device in result.keys():
            pem = result.get(device)
            try:
                elliptic_curve_key = load_pem_pubkey(pem)
            except TypeError:
                continue
            else:
                self.worker_devices.update({device: elliptic_curve_key})

    def process_exchange(self, pool_size=DEFAULT_POOL_SIZE):
        ip_base = self._local_network_ip_base
        manager_jobs = multiprocessing.Manager()
        ips_queue = manager_jobs.Queue()
        pool = multiprocessing.Pool(processes=DEFAULT_POOL_SIZE)

        for _ in range(1, pool_size):
            pool.apply_async(self.get_worker_devices, args=(ips_queue,), callback=self._worker_cb)

        for i in range(1, ADDRESSES_RANGE):
            ips_queue.put('{}{}'.format(ip_base, i))

        for process in range(1, pool_size):
            ips_queue.put(None)

        pool.close()
        pool.join()

    def get_worker_devices(self, ips_queue):
        worker_devices = {}

        while True:
            ip = ips_queue.get()
            if ip is None:
                return worker_devices
            url = 'http://{}:{}/assign_server_pubkey'.format(ip, CLIENT_APP_PORT)
            try:
                response = requests.post(url,
                                         data=(self.pubkey),
                                         headers={'Content-Type': 'application/octet-stream'},
                                         timeout=5)
            except requests.exceptions.ConnectionError:
                continue
            if not response.ok:
                continue
            try:
                content = response.json()
                pubkey = content.get('pubkey').encode()
            except (AttributeError, JSONDecodeError):
                continue
            else:
                worker_devices.update({ip: pubkey})


def process_keys_exchange(pubkey):
    exchange_manager = KeysExchangeManager(pubkey)
    exchange_manager.process_exchange()
    return exchange_manager.worker_devices
