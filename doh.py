#!/usr/bin/env python3

from dataclasses import dataclass

import sys
import os
import argparse
import socket
import select
import http.client
import json
import time
import logging
import errno
from multiprocessing import Queue
from typing import List, Tuple, Any, Dict
import threading
from threading import Lock, Event


try:
    from dnslib import DNSRecord, QTYPE, DNSHeader, RR, A
except ImportError:
    print("dnslib is missing")
    sys.exit(1)

DEFAULT_DOH = "dns.quad9.net:5053"
DEFAULT_PORT = 5053
DEFAULT_ADDR = "0.0.0.0"
DEFAULT_RESOLVERS = 10
DEFAULT_LOGGER = "doh"


@dataclass
class DohAnswer():
    name: str
    type: int
    ttl: int
    ip: str
    ts: float = time.time()

    def __repr__(self) -> str:
        return f"{self.ip}"

    def __str__(self) -> str:
        return "hello"


class DohConnection():

    def __init__(self, server: str) -> None:
        if(":" in server):
            (addr, port) = server.split(":")
            self.addr = addr
            self.port = int(port)
        else:
            self.addr = server
            self.port = 443
        self.headers = {"accept": "application/dns-json"}

        self.logger = logging.getLogger(DEFAULT_LOGGER)

    def __enter__(self) -> Any:
        self.conn = http.client.HTTPSConnection(self.addr, self.port)
        return self

    def __exit__(self, exc_type, exc_value, tb) -> bool:

        try:
            self.conn.close()
        finally:
            if(None != exc_type):
                raise(exc_value)

        return True

    def resolve(self, name: str, type: str = "A") -> List[DohAnswer]:

        info_list: List[DohAnswer] = []

        try:
            url = f"https://{self.addr}/dns-query?name={name}&type={type}"
            self.conn.request("GET", url, "", self.headers)
            response = self.conn.getresponse()
            json_str = response.read().decode("utf-8")
            response_dict = json.loads(json_str)

            if("Answer" in response_dict):
                for entry in response_dict["Answer"]:
                    if(entry["type"] != 1):
                        continue
                    e_name = entry["name"]
                    e_type = entry["type"]
                    #
                    # Adding an hour for TTL. Some are using very small
                    # value and it doesn't make sense to ask the server
                    # that often
                    #
                    e_ttl = entry["TTL"] + 3600
                    e_ip = entry["data"]
                    answer = DohAnswer(e_name, e_type, e_ttl, e_ip)
                    info_list.append(answer)
        except Exception as e:
            self.logger.exception(e)

        return info_list


class ResolveItem():

    name: str = ""
    answers: List[DohAnswer]

    def __init__(self, name: str) -> None:
        self.name = name
        self.event = Event()

    def signal(self) -> None:
        self.event.set()

    def wait(self, timeout=10) -> bool:
        return self.event.wait(timeout=timeout)

    def __str__(self) -> str:
        return f"{self.name}"


class DohCache():

    def __init__(self) -> None:
        self.mutex = Lock()
        self.cache: Dict[str, List[DohAnswer]] = {}
        self.logger = logging.getLogger(DEFAULT_LOGGER)

    def _expired(self, items: List[DohAnswer]) -> bool:
        cur_ts = time.time()
        expired_ts = items[0].ts + items[0].ttl

        if(expired_ts > cur_ts):
            return False
        return True

    def query(self, name: str) -> List[DohAnswer]:

        self.mutex.acquire()

        try:
            if(name in self.cache):
                if(False == self._expired(self.cache[name])):
                    return self.cache[name]
                else:
                    self.logger.info(f"{name} is expired")
                    del self.cache[name]

        finally:
            self.mutex.release()

        return []

    def update(self, name: str, answers: List[DohAnswer]) -> None:

        self.mutex.acquire()

        try:
            if(len(answers) > 0):
                self.cache[name] = answers
            else:
                if(name in self.cache):
                    del self.cache[name]
        finally:
            self.mutex.release()


class DohRequestThread(threading.Thread):

    def __init__(self, server: str, req_queue: Queue, res_queue: Queue, cache: DohCache) -> None:
        self.req_queue = req_queue
        self.res_queue = res_queue
        self.cache = cache
        self.server = server
        self.logger = logging.getLogger(DEFAULT_LOGGER)
        self.quit_signal = False
        super().__init__()

    def signal_quit(self) -> None:
        self.quit_signal = True

    def _process_query(self, con: DohConnection, data: bytes) -> bytes:

        request = DNSRecord.parse(data)
        response = DNSRecord(DNSHeader(id=request.header.id,
                                       qr=1, aa=1, ra=1), q=request.q)

        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]

        # cahed ?
        answers = self.cache.query(qname)

        if(len(answers) > 0):
            cached = True
        else:
            cached = False
            answers = con.resolve(qname)
            self.cache.update(qname, answers)

        self.logger.info(f"{qtype:<6} {qname} -> {answers} cached={cached}")

        if(0 != len(answers)):
            for a in answers:
                responde_data = RR(qname,
                                   rtype=a.type,
                                   ttl=a.ttl,
                                   rdata=A(a.ip))
                response.add_answer(responde_data)

        return response.pack()

    def run(self) -> None:

        with DohConnection(self.server) as con:
            try:
                while(False == self.quit_signal):
                    (request, client) = self.req_queue.get()
                    if(None != request):
                        response = self._process_query(con, request)
                        self.res_queue.put((response, client))
                    else:
                        # None = quit
                        break
            except Exception as e:
                self.logger.exception(e)


class DohResponseThread(threading.Thread):

    def __init__(self, socket: socket.socket, res_queue: Queue) -> None:
        self.queue = res_queue
        self.socket = socket
        self.logger = logging.getLogger(DEFAULT_DOH)
        super().__init__()

    def run(self) -> None:

        while(True):
            try:
                (response, client) = self.queue.get()

                if(None == response):
                    break
                self.socket.sendto(response, client)
            except Exception as e:
                self.logger.exception(e)


class DohQueue():

    def __init__(self, socket: socket.socket, doh_server: str, thread_count: int) -> None:
        self.server = doh_server
        self.thread_count = thread_count
        self.threads: List[DohRequestThread] = []
        self.cache = DohCache()
        self.socket = socket
        self.logger = logging.getLogger(DEFAULT_DOH)

    def put(self, request: bytes, client: Tuple[str, int]) -> None:
        self.req_queue.put((request, client))

    def get(self) -> Tuple[bytes, Tuple[str, int]]:
        return self.res_queue.get()

    def __enter__(self) -> Any:

        self.req_queue = Queue()
        self.res_queue = Queue()

        self.dequeue_thread = DohResponseThread(self.socket, self.res_queue)
        self.dequeue_thread.start()

        for _ in range(self.thread_count):
            t = DohRequestThread(self.server, self.req_queue,
                                 self.res_queue, self.cache)
            t.start()
            self.threads.append(t)
        return self

    def __exit__(self, exc_type, exc_value, tb) -> bool:

        for i in range(self.thread_count):
            self.threads[i].signal_quit()
            self.req_queue.put((None, None))

        for i in range(self.thread_count):
            self.threads[i].join()

        self.res_queue.put((None, None))

        self.dequeue_thread.join()

        self.req_queue.close()
        self.res_queue.close()

        if(None != exc_value):
            raise exc_value

        return True


class DnsServer():

    def __init__(self, addr: Tuple[str, int], server: str, thread_count: int) -> None:
        self.addr = addr
        self.server = server
        self.thread_count = thread_count
        self.logger = logging.getLogger(DEFAULT_LOGGER)

    def __enter__(self) -> Any:
        self.cache = DohCache()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        return self

    def __exit__(self, exc_type, exc_value, tb) -> bool:
        self.socket.close()
        if(None != exc_type):
            raise exc_value
        return True

    def loop(self) -> None:

        self.socket.bind(self.addr)
        self.socket.setblocking(False)

        try:
            with DohQueue(self.socket, self.server, self.thread_count) as q:
                while(True):
                    r, _, _ = select.select([self.socket], [], [], 5)
                    if(len(r) > 0):
                        data, client = self.socket.recvfrom(4096)
                        if(len(data) > 0):
                            try:
                                q.put(data, client)
                            except Exception as e:
                                self.logger.exception(e)
                        else:
                            pass  # Nothing to read
                    else:
                        pass  # Probably a timeout
        except Exception as e:
            self.logger.exception(e)
        except KeyboardInterrupt:
            self.logger.info("User interrupted")
            pass


def main() -> int:
    status = 1

    parser = argparse.ArgumentParser()

    parser.add_argument("-p",
                        "--port",
                        default=DEFAULT_PORT,
                        required=False,
                        type=int,
                        help=f"Listening port. Default: {DEFAULT_PORT}")

    parser.add_argument("-a",
                        "--addr",
                        default=DEFAULT_ADDR,
                        required=False,
                        type=str,
                        help=f"Listening address. Default: {DEFAULT_ADDR}")

    parser.add_argument("-s",
                        "--doh-server",
                        default=DEFAULT_DOH,
                        type=str,
                        required=False,
                        help=f"DoH server. Default: {DEFAULT_DOH}")

    parser.add_argument("--resolver-threads",
                        default=DEFAULT_RESOLVERS,
                        type=int,
                        required=False,
                        help=f"Resolver threads Default: {DEFAULT_RESOLVERS}")

    args = parser.parse_args()

    logfile = os.path.dirname(sys.argv[0])
    logfile = os.path.abspath(logfile)
    logfile = os.path.join(logfile, "doh.log")

    logging.basicConfig(filename=logfile,
                        filemode='a',
                        format='%(asctime)s %(message)s',
                        datefmt='%H:%M:%S',
                        level=logging.DEBUG)

    logger = logging.getLogger(DEFAULT_LOGGER)
    logger.info("Server started")

    #
    # Work
    #
    try:
        with DnsServer((args.addr, args.port),
                       args.doh_server,
                       args.resolver_threads) as server:
            server.loop()
        status = 0
    except PermissionError:
        print(f"Error: Permission failure binding port {args.port}")
    except OSError as e:
        if(errno.EADDRINUSE == e.errno):
            print(f"Error: port {args.port} already bound")
        else:
            raise e
    return status


if __name__ == '__main__':
    status = main()

    if(0 != status):
        sys.exit(status)
