import multiprocessing
import requests
import socket
import re

from ecies import decrypt

DNS = "8.8.8.8"
DEFAULT_POOL_SIZE = 255
ADDRESSES_RANGE = 255
CLIENT_APP_PORT = 5000


class LookupManager():
    """This class performs network lookup.


    Attributes
    ----------
    network_ips : list
        List of network ip's

    """
    def __init__(self, pubkey, prvkey):
        self. machine_identifers = {}
        self.pubkey = pubkey
        self.prvkey = prvkey

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
        self.machine_identifers.update(result)

    def process_lookup(self, pool_size=DEFAULT_POOL_SIZE):
        ip_base = self._local_network_ip_base
        manager_jobs = multiprocessing.Manager()
        ips_queue = manager_jobs.Queue()
        pool = multiprocessing.Pool(processes=DEFAULT_POOL_SIZE)

        for _ in range(1, pool_size):
            pool.apply_async(self.get_machine_identifer, args=(ips_queue,), callback=self._worker_cb)

        for i in range(1, ADDRESSES_RANGE):
            ips_queue.put('{}{}'.format(ip_base, i))

        for process in range(1, pool_size):
            ips_queue.put(None)

        pool.close()
        pool.join()

    def get_machine_identifer(self, ips_queue):
        """Ping worker implementation.

        Parameters
        ----------
        jobs_queue : Queue

        Returns
        -------
        None
        """
        machine_identifers = {}

        while True:
            ip = ips_queue.get()
            if ip is None:
                return machine_identifers
            url = 'http://{}:{}/encrypted_identifer'.format(ip, CLIENT_APP_PORT)
            try:
                response = requests.post(url,
                                         data=self.pubkey.encode(),
                                         headers={'Content-Type': 'application/octet-stream'},
                                         timeout=5)
            except requests.exceptions.ConnectionError:
                continue
            if not response.ok:
                continue
            encrypted_machine_identifer = response.content
            machine_identifer = decrypt(self.prvkey, encrypted_machine_identifer)
            machine_identifers.update({ip: machine_identifer.decode()})


def lookup(pubkey, prvkey):
    lookup_manager = LookupManager(pubkey, prvkey)
    lookup_manager.process_lookup()
    return lookup_manager.machine_identifers
