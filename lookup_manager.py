import multiprocessing
import subprocess
import socket
import os
import re


LOCALHOST = "8.8.8.8"
LOCALHOST_PORT = 80
DEFAULT_POOL_SIZE = 255
ADDRESSES_RANGE = 255


def ping_worker(jobs_queue):
    """Ping worker implementation.

    Parameters
    ----------
    jobs_queue : Queue
    results_queue : Queue

    Returns
    -------
    None
    """
    DEVNULL = open(os.devnull, 'w')
    results = []
    while True:
        ip = jobs_queue.get()

        if ip is None:
            return results
        try:
            subprocess.check_call(['ping', '-c1', ip], stdout=DEVNULL)
        except subprocess.CalledProcessError:
            pass
        else:
            results.append(ip)


class LookupManager():
    """This class performs network lookup.


    Attributes
    ----------
    network_ips : list
        List of network ip's

    """
    def __init__(self):
        self.network_ips = []

    @property
    def localhost_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((LOCALHOST, LOCALHOST_PORT))
        ip = s.getsockname()[0]
        s.close()
        return ip

    @property
    def _local_network_ip_base(self):
        return re.sub('[^.]*$', '', self.localhost_ip)

    def _worker_cb(self, result):
        self.network_ips.extend(result)

    def process_lookup(self, pool_size=DEFAULT_POOL_SIZE):
        ip_base = self._local_network_ip_base
        manager_jobs = multiprocessing.Manager()
        jobs_queue = manager_jobs.Queue()
        pool = multiprocessing.Pool(processes=DEFAULT_POOL_SIZE)

        for _ in range(1, pool_size):
            pool.apply_async(ping_worker, args=(jobs_queue,), callback=self._worker_cb)

        for i in range(1, ADDRESSES_RANGE):
            jobs_queue.put('{}{}'.format(ip_base, i))

        for process in range(1, pool_size):
            jobs_queue.put(None)

        pool.close()
        pool.join()


def lookup():
    lookup_manager = LookupManager()
    lookup_manager.process_lookup()
    return lookup_manager.network_ips


if __name__ == '__main__':
    print(lookup())
