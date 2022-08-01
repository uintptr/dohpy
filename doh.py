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
import threading
import urllib.parse
import pwd

from typing import List, Tuple, Any, Dict
from queue import Queue

try:
    from dnslib import DNSRecord, QTYPE, DNSHeader, RR, A
except ImportError:
    print("dnslib is missing")
    sys.exit(1)

VERSION_STR = "0.1"
DEFAULT_DOH = "https://dns.quad9.net:5053/dns-query"
DEFAULT_PORT = 5053
DEFAULT_ADDR = "127.0.0.1"
DEFAULT_RESOLVERS = 20
DEFAULT_LOGGER = "doh"

#
# Some have meme level expiry values and makes caching somewhat irrelevant.
# Adding a few hours so we don't have to request the doh server that often
#
DEFAULT_EXTRA_EXPIRY = (5 * 3600)


class DohPermissionDenied(Exception):
    pass


def printkv(n, v) -> None:
    name = f"{n}:"
    print(f"    {name:<20} {v}")


@dataclass
class DohAnswer():
    name: str
    type: int
    ttl: int
    ip: str
    ts: float = time.time()

    def __repr__(self) -> str:
        return f"{self.ip}"


class DohConnection():

    def __init__(self, doh_url: str) -> None:

        self.url = urllib.parse.urlparse(doh_url)

        if(None != self.url.port):
            self.port = self.url.port
        else:
            # it's Dns over HTTPS after all
            self.port = 443

        self.headers = {"accept": "application/dns-json"}
        self.logger = logging.getLogger(DEFAULT_LOGGER)

    def _connect(self) -> http.client.HTTPSConnection:
        server = str(self.url.hostname)
        return http.client.HTTPSConnection(server, self.url.port, timeout=5)

    def __enter__(self) -> Any:
        self.conn = self._connect()
        return self

    def __exit__(self, exc_type, exc_value, tb) -> bool:

        try:
            self.conn.close()
        finally:
            if(None != exc_type):
                raise(exc_value)

        return True

    def _resolve_name(self, name: str, type: str = "A") -> List[DohAnswer]:
        answers: List[DohAnswer] = []

        url = f"{self.url.scheme}://{self.url.hostname}"
        url += f"{self.url.path}?name={name}&type={type}"
        self.conn.request("GET", url, "", self.headers)
        response = self.conn.getresponse()
        json_str = response.read().decode("utf-8")
        response_dict = json.loads(json_str)

        if(0 != response_dict["Status"]):
            return []

        status = response_dict["Status"]

        if(0 != status):
            self.logger.info(f"{name} status={status}")

        if("Answer" not in response_dict):
            return []

        for entry in response_dict["Answer"]:
            if(entry["type"] != 1):
                continue
            e_name = entry["name"]
            e_type = entry["type"]
            e_ttl = entry["TTL"] + DEFAULT_EXTRA_EXPIRY
            e_ip = entry["data"]
            answer = DohAnswer(e_name, e_type, e_ttl, e_ip)
            answers.append(answer)

        return answers

    def _resolve_loop(self, name: str, type: str = "A") -> List[DohAnswer]:
        answers: List[DohAnswer] = []
        attempts = 3
        success = False
        hostname = self.url.hostname

        while(False == success and attempts > 0):
            try:
                answers = self._resolve_name(name, type)
                success = True
            except http.client.CannotSendRequest:
                self.logger.info("Can't send request")
            except http.client.RemoteDisconnected:
                self.logger.info("Remote server disconnected")
            except TimeoutError:
                self.logger.info("Connection timed out")
            except OSError as e:
                if(errno.ENETUNREACH == e.errno):
                    self.logger.info(f"{hostname} is not reachable")
                elif(errno.ECONNRESET == e.errno):
                    self.logger.info("Server resetted the connection")
                elif(errno.EPIPE == e.errno):
                    self.logger.info("Broken pipe")
                else:
                    self.logger.exception(e)
            except Exception as e:
                self.logger.exception(e)
            finally:
                if(False == success):
                    attempts -= 1
                    self.logger.info(f"reconnecting to {hostname}")
                    self.conn.close()
                    self.conn = self._connect()

        return answers

    def resolve(self, name: str, type: str = "A") -> List[DohAnswer]:
        return self._resolve_loop(name, type)


class DohCache():

    def __init__(self) -> None:
        self.mutex = threading.Lock()
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
                    self.logger.info(f"{name} expired")
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

    def __init__(self, doh_url: str, req_queue: Queue, res_queue: Queue, cache: DohCache, name=None) -> None:
        self.req_queue = req_queue
        self.res_queue = res_queue
        self.cache = cache
        self.doh_url = doh_url
        self.logger = logging.getLogger(DEFAULT_LOGGER)
        self.quit_signal = False
        super().__init__(name=name)

    def signal_quit(self) -> None:
        self.quit_signal = True

    def _process_query(self, con: DohConnection, data: bytes) -> bytes:

        request = DNSRecord.parse(data)
        response = DNSRecord(DNSHeader(id=request.header.id,
                                       qr=1, aa=1, ra=1), q=request.q)

        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]

        if(qname.endswith(".arpa.") or qname.endswith(".local")):
            return response.pack()

        # cahed ?
        answers = self.cache.query(qname)

        if(len(answers) > 0):
            cached = True
            delay = 0
        else:
            cached = False
            pre = time.time()
            answers = con.resolve(qname)
            delay = 1000 * (time.time() - pre)
            self.cache.update(qname, answers)

        log_str = f"{qtype:<6} {qname} -> {answers}"

        if(True == cached):
            log_str += " (cached)"
        else:
            log_str += f" ({delay:0.2f}ms)"

        self.logger.info(log_str)

        if(0 != len(answers)):
            for a in answers:
                responde_data = RR(qname,
                                   rtype=a.type,
                                   ttl=a.ttl,
                                   rdata=A(a.ip))
                response.add_answer(responde_data)

        return response.pack()

    def run(self) -> None:

        with DohConnection(self.doh_url) as con:
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
        super().__init__(name="response")

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

    def __init__(self, socket: socket.socket, doh_url: str, thread_count: int) -> None:
        self.doh_url = doh_url
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

        for i in range(self.thread_count):
            name = f"resolver_{i}"
            t = DohRequestThread(self.doh_url, self.req_queue,
                                 self.res_queue, self.cache, name=name)
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
        self.socket.bind(self.addr)
        self.socket.setblocking(False)
        return self

    def __exit__(self, exc_type, exc_value, tb) -> bool:
        self.socket.close()
        if(None != exc_type):
            raise exc_value
        return True

    def loop(self) -> None:

        try:
            with DohQueue(self.socket, self.server, self.thread_count) as q:
                while(True):
                    r, _, _ = select.select([self.socket], [], [])
                    if(len(r) > 0):
                        data, client = self.socket.recvfrom(4096)
                        if(len(data) > 0):
                            #
                            # Response will be issued by a thread. We
                            # don't have to worry about it here
                            #
                            q.put(data, client)
                        else:
                            pass  # Nothing to read. Is this fatal ?
        except Exception as e:
            self.logger.exception(e)
        except KeyboardInterrupt:
            self.logger.info("User interrupted")
            pass


def drop_privileges(user='nobody') -> None:

    # If not running as root we have nothing to do
    if(0 != os.getuid()):
        return

    # Get the uid/gid from the name
    pw_entry = pwd.getpwnam(user)

    # Remove group privileges
    os.setgroups([])

    # Try setting the new uid/gid
    os.setgid(pw_entry.pw_gid)
    os.setuid(pw_entry.pw_uid)

    # Ensure a very conservative umask
    os.umask(0o077)


def main() -> int:
    status = 1

    parser = argparse.ArgumentParser()

    if("USER" in os.environ):
        current_user = os.environ["USER"]
    else:
        current_user = "nobody"

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
                        "--doh-url",
                        default=DEFAULT_DOH,
                        type=str,
                        required=False,
                        help=f"DoH URL. Default: {DEFAULT_DOH}")

    parser.add_argument("--resolver-threads",
                        default=DEFAULT_RESOLVERS,
                        type=int,
                        required=False,
                        help=f"Resolver threads Default: {DEFAULT_RESOLVERS}")

    parser.add_argument("-v",
                        "--verbose",
                        action="store_true",
                        help="Log to stdout")

    parser.add_argument("-u",
                        "--user",
                        default=current_user,
                        required=False,
                        type=str,
                        help=f"Can't run as root. Default: {current_user}")

    args = parser.parse_args()

    print(f"dohpy v{VERSION_STR}")
    printkv("Listening Address", args.addr)
    printkv("Listening Port", args.port)
    printkv("DOH URL", args.doh_url)
    printkv("# Threads", args.resolver_threads)
    printkv("Run as user", args.user)
    printkv("Verbose", args.verbose)

    logfile = os.path.dirname(sys.argv[0])
    logfile = os.path.abspath(logfile)
    logfile = os.path.join(logfile, "doh.log")

    logging.basicConfig(filename=logfile,
                        filemode='a',
                        format='%(asctime)s %(threadName)-15s %(message)s',
                        datefmt='%H:%M:%S',
                        level=logging.DEBUG)

    logger = logging.getLogger(DEFAULT_LOGGER)

    if(True == args.verbose):
        logger.addHandler(logging.StreamHandler(sys.stdout))

    logger.info("Server started")

    try:
        with DnsServer((args.addr, args.port),
                       args.doh_url,
                       args.resolver_threads) as server:
            drop_privileges(args.user)
            server.loop()
        status = 0
    except PermissionError:
        print(f"Error: Permission failure binding port {args.port}")
    except OSError as e:
        if(errno.EADDRINUSE == e.errno):
            print(f"Error: port {args.port} already bound")
        else:
            raise e
    except DohPermissionDenied as e:
        print("Error", e)
    return status


if __name__ == '__main__':
    status = main()

    if(0 != status):
        sys.exit(status)
