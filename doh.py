#!/usr/bin/env python3

from asyncio.log import logger
from dataclasses import dataclass
import sys
import os
import argparse
import socket
import select
import http.client
import json
from syslog import LOG_AUTH, LOG_INFO
import time
import errno
import urllib.request
import logging

from typing import List, Tuple, Any, Dict
import threading
from threading import Lock, Event

try:
    from dnslib import DNSRecord, QTYPE, DNSHeader, RR, A
except ImportError:
    print("dnslib is missing")
    sys.exit(1)

DEFAULT_DOH = "cloudflare-dns.com"
DEFAULT_PORT = 5053
DEFAULT_ADDR = "0.0.0.0"
DEFAULT_RESOLVERS = 10
DEFAULT_LOGGER = "doh"


class DohQueue():

    def __init__(self) -> None:
        self.mutex = Lock()
        self.event = Event()
        self.queue = []
        self.quit = Event()

    def close(self) -> None:
        self.quit.set()

    def put(self, item) -> None:
        self.mutex.acquire()

        try:
            self.queue.append(item)
        finally:
            self.mutex.release()

        self.event.set()

    def get(self, timeout=1) -> Any:

        item = None

        while (None == item and False == self.quit.is_set()):
            self.event.wait(timeout)

            if(False == self.quit.is_set()):
                self.mutex.acquire()
                try:
                    if(len(self.queue) > 0):
                        item = self.queue.pop()
                finally:
                    self.mutex.release()

        return item


@dataclass
class DohAnswer():
    name: str
    type: int
    ttl: int
    ip: str
    ts: float = time.time()

    def __repr__(self) -> str:
        return f"ttl={self.ttl} ip={self.ip}"

    def __str__(self) -> str:
        return "hello"


class DohConnection():

    def __init__(self, server: str) -> None:
        self.server = server
        self.headers = {"accept": "application/dns-json"}
        self.conn = http.client.HTTPSConnection(server, 443)
        self.logger = logging.getLogger(DEFAULT_LOGGER)

    def resolve(self, name: str, type: str = "A") -> List[DohAnswer]:

        info_list: List[DohAnswer] = []

        try:
            url = f"https://{self.server}/dns-query?name={name}&type={type}"
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
            logger.exception(e)

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


def resolver_thread(queue: DohQueue, server: str, quit: Event) -> None:

    r = DohConnection(server)

    while(False == quit.is_set()):
        item: ResolveItem = queue.get()
        if(None != item):
            item.answers = r.resolve(item.name)
            item.signal()


class DohResolver():

    def __init__(self, server: str, thread_count: int):
        self.server = server
        self.thread_count = thread_count
        self.threads = []

    def __enter__(self) -> Any:
        self.quit = Event()
        self.queue = DohQueue()

        thread_args = (self.queue, self.server, self.quit)

        for _ in range(self.thread_count):
            t = threading.Thread(target=resolver_thread, args=thread_args)
            t.start()
            self.threads.append(t)

        return self

    def __exit__(self, exc_type, exc_value, tb) -> bool:

        try:
            self.queue.close()
            self.quit.set()
            #
            # Join resolvers
            #
            for i in range(self.thread_count):
                self.threads[i].join()

        finally:
            if(None != exc_type):
                raise exc_value

        return True

    def resolve(self, name: str) -> List[DohAnswer]:
        item = ResolveItem(name)
        self.queue.put(item)
        if ( True == item.wait()):
            return item.answers
        return []


class DohCache():

    def __init__(self) -> None:
        self.mutex = Lock()
        self.cache:Dict[str,List[DohAnswer]] = {}
        self.logger = logging.getLogger(DEFAULT_LOGGER)

    def _expired(self, items:List[DohAnswer] ) -> bool:
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

    def update(self, name:str, answers:List[DohAnswer]) -> None:

        self.mutex.acquire()

        try:
            if(len(answers)>0):
                self.cache[name] = answers
            else:
                if(name in self.cache):
                    del self.cache[name]
        finally:
            self.mutex.release()


class DnsServer():

    def __init__(self, resolver: DohResolver, addr: Tuple[str, int]) -> None:
        self.addr = addr
        self.resolver = resolver
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

    def _request_handler(self, data: bytes) -> bytes:

        request = DNSRecord.parse(data)
        response = DNSRecord(DNSHeader(id=request.header.id,
                                       qr=1, aa=1, ra=1), q=request.q)

        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]

        # cahed ?
        answers = self.cache.query(qname)

        if(len(answers) > 0 ):
            cached = True
        else:
            cached = False
            answers = self.resolver.resolve(qname)
            self.cache.update(qname, answers)

        self.logger.info(f"{qtype:<6} {qname} -> {answers} cached={cached}")

        if(0 != len(answers)):
            for a in answers:
                responde_data = RR( qname,
                                    rtype=a.type,
                                    ttl=a.ttl,
                                    rdata=A(a.ip))
                response.add_answer(responde_data)

        return response.pack()

    def loop(self) -> None:

        self.socket.bind(self.addr)
        self.socket.setblocking(False)

        try:
            while(True):
                r, _, _ = select.select([self.socket], [], [], 5)
                if(len(r) > 0):
                    data, client = self.socket.recvfrom(4096)
                    if(len(data) > 0):
                        try:
                            response = self._request_handler(data)
                            self.socket.sendto(response, client)
                        except Exception as e:
                            self.logger.exception(e)
                    else:
                        pass  # Nothing to read
                else:
                    pass  # Probably a timeout
        except Exception as e:
            self.logger.exception(e)
        except KeyboardInterrupt:
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
                        type=str,
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
        with DohResolver(args.doh_server, args.resolver_threads) as r:
            addr = (args.addr, args.port)
            with DnsServer(r, addr) as server:
                server.loop()
        status = 0
    except PermissionError as e:
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
