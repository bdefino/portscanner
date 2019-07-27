#!/bin/python2
import json
import socket
import sys
import thread
import time

__doc__ = """simple port scanning
Usage: ./portscanner.py MODE/PROTO [OPTIONS]
GENERAL OPTIONS
    -a, --address=ADDRESS|SUBNET
        the address (or subnet, using "ADDRESS/MASK" notation) to scan
    -j, --json
        print results in JSON format
        (defaults to a more readable format)
    -p, --ports=PORTS
        a comma-separated list of ports,
        with ranges denoted by hyphens
        e.g. for ports 1 to 3 and 5: "1-3,5"
RESPONSE MODE OPTIONS
        --prompt=PROMPT
            optional prompt for a response
    -r, --recvlen=LENGTH
        number of bytes to receive
        (default attempts to read everything until the socket is closed)
TCP PROTO MODES
    connect
        attempts to create a connection with each peer
    response
        attempts to create a connection with each peer,
        if specified, a prompt is sent before receiving bytes
TCP PROTO OPTIONS
    -t, --timeout=TIMEOUT
        optional timeout
UDP PROTO MODES
    response
        if specified, a prompt is sent before receiving bytes"""

PROMPT = None
RECVLEN = -1
THREADEDLOADDIST_CAPACITY = 10
TIMEOUT = None

def _detect_af(addr):
    if len(addr) == 2:
        return socket.AF_INET
    elif len(addr) == 4:
        return socket.AF_INET6
    raise ValueError("unrecognized address family")

def _generate_addrs_with_ports(addrs, *ports):
    for addr in addrs:
        addr = list(addr)
        
        for port in ports:
            addr[1] = port
            yield tuple(addr)

def _load_addr(s):
    return socket.getaddrinfo(s, 0)[0][4] # zero out everything

def _load_subnet(s):
    addr = s
    masklen = None
    
    if '/' in s:
        addr, masklen = s.split('/', 1)

        if '/' in masklen:
            raise ValueError("invalid subnet")
    addr = _load_addr(addr)

    if masklen is None:
        masklen = 128 if _detect_af(addr) == socket.AF_INET6 else 32
    return Subnet(addr, _mkmask(_detect_af(addr), int(masklen)))

def main(argv):
    addrs = None
    argv = list(argv[1:])
    _gettext = lambda r: r.pretty_str()
    mode = None
    ports = []
    proto = None
    scankwargs = {}
    scantype = None

    if len(argv) < 2:
        print __doc__
        sys.exit(1)
    mode, proto = argv[0].lower().split('/', 1)
    del argv[0]
    
    if proto == "tcp":
        if mode == "connect":
            scantype = TCPConnectScan
        elif mode == "response":
            scantype = TCPResponseScan
        else:
            print "Unsupported TCP mode."
            sys.exit(1)
        i = 0

        while i < len(argv):
            arg = argv[i]
            
            if arg.startswith("-t"):
                try:
                    scankwargs["timeout"] = float(arg[len("-t"):] \
                        if len(arg) > len("-t") else argv.pop(i + 1))
                except IndexError:
                    print "Expected argument."
                    print __doc__
                    sys.exit(1)
                except ValueError:
                    print "Bad argument."
                    print __doc__
                    sys.exit(1)
                del argv[i]
                continue
            elif arg.startswith("--timeout="):
                try:
                    scankwargs["timeout"] = float(arg[len("--timeout="):])
                except ValueError:
                    print "Bad argument."
                    print __doc__
                    sys.exit(1)
                del argv[i]
                continue
            i += 1
    elif proto == "udp":
        if mode == "response":
            scantype = UDPResponseScan
        else:
            print "Unsupported UDP mode."
            sys.exit(1)
    else:
        print "Unsupported protocol."
        sys.exit(1)
    i = 0

    while i < len(argv):
        arg = argv[i]
        
        if arg.startswith("-a"):
            try:
                addrs = _load_subnet(arg[len("-a"):] \
                    if len(arg) > len("-a") else argv.pop(i + 1))
            except IndexError:
                print "Expected argument."
                print __doc__
                sys.exit(1)
            except ValueError:
                print "Bad argument."
                print __doc__
                sys.exit(1)
            del argv[i]
            continue
        elif arg.startswith("--address="):
            try:
                addrs = _load_subnet(arg[len("--address="):])
            except ValueError:
                print "Bad argument."
                print __doc__
                sys.exit(1)
            del argv[i]
            continue
        elif arg in ("-j", "--json"):
            _gettext = lambda r: str(r)
            del argv[i]
            continue
        elif arg.startswith("-p"):
            try:
                ports = _parse_int_range_csv(arg[len("-p"):] \
                    if len(arg) > len("-p") else argv.pop(i + 1))
            except IndexError:
                print "Expected argument."
                print __doc__
                sys.exit(1)
            except ValueError:
                print "Bad argument."
                print __doc__
                sys.exit(1)
            del argv[i]
            continue
        elif arg.startswith("--ports="):
            try:
                ports = _parse_int_range_csv(arg[len("--ports="):])
            except ValueError:
                print "Bad argument."
                print __doc__
                sys.exit(1)
            del argv[i]
            continue
        i += 1

    if mode == "response":
        i = 0
        
        while i < len(argv):
            arg = argv[i]
            
            if arg.startswith("--prompt="):
                try:
                    scankwargs["prompt"] = arg[len("--prompt="):]
                except ValueError:
                    print "Bad argument."
                    print __doc__
                    sys.exit(1)
                del argv[i]
                continue
            elif arg.startswith("-r"):
                try:
                    scankwargs["recvlen"] = int(arg[len("-r"):] \
                        if len(arg) > len("-r") else argv.pop(i + 1))
                except IndexError:
                    print "Expected argument."
                    print __doc__
                    sys.exit(1)
                except ValueError:
                    print "Bad argument."
                    print __doc__
                    sys.exit(1)
                del argv[i]
                continue
            elif arg.startswith("--recvlen="):
                try:
                    scankwargs["recvlen"] = int(arg[len("--recvlen="):])
                except ValueError:
                    print "Bad argument."
                    print __doc__
                    sys.exit(1)
                del argv[i]
                continue
            i += 1

    if not addrs:
        print "Expected an address."
        sys.exit(1)
    elif not ports:
        print argv
        print "Expected a port."
        sys.exit(1)

    for result in Scanner(ThreadedLoadDist(), scantype(**scankwargs))(
            _generate_addrs_with_ports(addrs, *ports)):
        print _gettext(result)
        sys.stdout.flush()

def _mkmask(af, length = -1):
    total = 32

    if af == socket.AF_INET6:
        total = 128
    elif not af == socket.AF_INET:
        raise ValueError("unrecognized address family")
    mask = bytearray(total / 8)

    for i in range(length if length >= 0 else total):
        mask[i / 8] |= 1 << (i % 8)
    return '.'.join((str(c) for c in mask))

def _pack(i, length = -1):
    h = "%x" % i
    h = h.zfill(len(h) + len(h) % 2)
    return h.decode("hex")

def _parse_int_range_csv(csv):
    _set = set()

    for e in csv.split(','):
        if '-' in e:
            start, end = e.split('-', 1)
            
            if '-' in end:
                raise ValueError("multiple hyphens in int-range CSV")

            for n in range(int(start), int(end)):
                _set.add(n)
        else:
            _set.add(int(e))
    return sorted(_set)

def _try_close_sock(sock):
    for attr, args in (("shutdown", (socket.SHUT_RDWR, )), ("close", ())):
        try:
            getattr(sock, attr)(*args)
        except:
            pass

def _unpack(a):
    h = str(a).encode("hex")
    h = h.zfill(len(h) + len(h) % 2)
    return int(h, 16)

class LoadDist:
    def __init__(self):
        pass

    def __call__(self, func, *args, **kwargs):
        """execute a task via the load distribution system"""
        raise NotImplementedError

class FauxLoadDist(LoadDist):
    def __call__(self, func, *args, **kwargs):
        """execute a task"""
        func(*args, **kwargs)

class Scan:
    def __init__(self):
        pass

    def __call__(self, addr):
        """return ScanResults instance for the specified address"""
        raise NotImplementedError

class ResponseScan(Scan):
    def __init__(self, prompt = None, recvlen = RECVLEN):
        Scan.__init__(self)
        self.prompt = prompt
        self.recvlen = recvlen

class Scanner:
    def __init__(self, loaddist = None, *scans):
        self._loaddist = loaddist if loaddist else FauxLoadDist()
        self.scans = scans

    def __call__(self, addrs):
        """generate ScanResult instances for the specified addresses"""
        for addr in addrs:
            for scan in self.scans:
                yield scan(addr)

class ScanResults(dict):
    def pretty_str(self):
        _vencode = lambda v: "\"%s\"" % v.encode("unicode-escape") \
            if isinstance(v, str) else str(v)
        return '\n'.join(["ScanResults:"] + ["\t%s: %s" % (str(k), _vencode(v))
            for k, v in sorted(self.iteritems(), key = lambda e: e[0])])
    
    def __str__(self):
        return json.dumps(self)

class Subnet:
    def __init__(self, addr, mask):
        self.addr = addr
        self.mask = mask
        self._naddr = bytearray(socket.inet_pton(_detect_af(self.addr),
            str(self.addr[0])))
        self._nmask = bytearray(socket.inet_pton(_detect_af(self.addr),
            str(self.mask)))

    def __iter__(self):
        _cur = bytearray(self._naddr)

        for i, m in enumerate(self._nmask):
            _cur[i] &= m
        _max = bytearray(_cur)
        for i in range(8 * len(self._nmask) - 1, -1, -1):
            bit = 1 << (i % 8)
            o = i / 8

            if bit & self._nmask[o]:
                break
            _max[o] |= bit
        self._cur = _unpack(_cur)
        self._max = _unpack(_max)
        return self

    def next(self):
        if not hasattr(self, "_cur") or not hasattr(self, "_max"):
            raise AttributeError("Subnet instance has no attribute \"next\"")

        if self._cur > self._max:
            raise StopIteration
        self._cur += 1
        return (socket.inet_ntop(_detect_af(self.addr), _pack(self._cur - 1,
            len(self._naddr))), ) + self.addr[1:]

class TCPScan(Scan):
    def __init__(self, timeout = None):
        Scan.__init__(self)
        self.timeout = timeout

class TCPConnectScan(TCPScan):
    """
    obtains results of the form:
        ScanResults(connected = <boolean>, peername = <address>,
            scantype = "TCPConnectScan", timeout = <number>)
    """
    def __call__(self, addr):
        results = ScanResults(connected = False, peername = addr,
            scantype = "TCPConnectScan", timeout = self.timeout)
        sock = None
        
        try:
            sock = socket.socket(_detect_af(addr), socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect(addr)
            results["connected"] = True
        except socket.error:
            pass
        finally:
            if sock:
                _try_close_sock(sock)
        return results

class TCPResponseScan(ResponseScan, TCPScan):
    """
    obtains results of the form:
        ScanResults(connected = <boolean>, peername = <address>,
            prompt = <null or string>, recvlen = <number>,
            response = <null or string>, scantype = "TCPResponseScan",
            timeout = <number>)
    """
    
    def __init__(self, prompt = PROMPT, recvlen = RECVLEN, timeout = TIMEOUT):
        ResponseScan.__init__(self, prompt, recvlen)
        TCPScan.__init__(self, timeout)

    def __call__(self, addr):
        results = ScanResults(connected = False, peername = addr,
            prompt = self.prompt, recvlen = self.recvlen, response = None,
            scantype = "TCPResponseScan", sent = 0, timeout = self.timeout)
        sock = None

        try:
            sock = socket.socket(_detect_af(addr), socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect(addr)
            results["connected"] = True

            if self.prompt is not None:
                sock.sendall(self.prompt)
            results["response"] = sock.recv(self.recvlen)
        except socket.error:
            pass
        finally:
            if sock:
                _try_close_sock(sock)
        return results

class ThreadedLoadDist(LoadDist):
    def __init__(self, capacity = THREADEDLOADDIST_CAPACITY):
        self.capacity = capacity
        self.count = 0
        self._mutex = thread.allocate_lock()

    def __call__(self, func, *args, **kwargs):
        while 1:
            self._mutex.acquire()

            if self.count < self.capacity:
                self.count += 1
                self._mutex.release()
                break
            self._mutex.release()
            time.sleep(0.001)
        thread.start_new_thread(self._handle_call, (func, ) + args, kwargs)

    def _handle_call(self, func, *args, **kwargs):
        LoadDist.__call__(func, *args, **kwargs)
        self._mutex.acquire()
        self.count -= 1
        self._mutex.release()
        thread.exit()

class UDPScan(Scan):
    pass

class UDPResponseScan(ResponseScan, UDPScan):
    """
    obtains results of the form:
        ScanResults(connected = <boolean>, peername = <address>,
            prompt = <null or string>, recvlen = <number>,
            response = <null or string>, scantype = "UDPresponseScan",
            sent = <number>)
    """
    
    def __init__(self, prompt = None, recvlen = None):
        ResponseScan.__init__(self, prompt, recvlen)
        UDPScan.__init__(self)

    def __call__(self, addr):
        results = ScanResults(connected = False, peername = None,
            prompt = self.prompt, recvlen = self.recvlen, response = None,
            scantype = "UDPresponseScan", sent = 0)
        sock = None

        try:
            sock = socket.socket(_detect_af(addr), socket.SOCK_DGRAM)

            if self.prompt is not None:
                results["sent"] = sock.sendto(self.prompt, addr)
            results["response"], results["peername"] = \
                sock.recvfrom(self.recvlen)
        except socket.error: # should be unreachable
            pass
        finally:
            if sock:
                _try_close_sock(sock)
        return results

if __name__ == "__main__":
    main(sys.argv)
