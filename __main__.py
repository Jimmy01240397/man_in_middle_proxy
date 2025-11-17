import socket
import sys
import ssl
import io
import dpkt.http
import yaml
import re
import gzip

buffer_size = 1

if len(sys.argv) <= 1:
    print(f"usage: {sys.argv[0]} <config file>")
    exit()

def parse_ip_port(address):
    ipv6_pattern = r'^\[([0-9a-fA-F:]+)\](?::(\d+))?$'
    ipv4_pattern = r'^([0-9\.]+)(?::(\d+))?$'
    domain_pattern = r'^([a-zA-Z0-9\-\.]+)(?::(\d+))?$'

    ipv6_match = re.match(ipv6_pattern, address)
    ipv4_match = re.match(ipv4_pattern, address)
    domain_match = re.match(domain_pattern, address)
    if ipv6_match:
        host = ipv6_match.group(1)
        port = ipv6_match.group(2)
    elif ipv4_match:
        host = ipv4_match.group(1)
        port = ipv4_match.group(2)
    elif domain_match:
        host = domain_match.group(1)
        port = domain_match.group(2)
    else:
        raise ValueError(f"Invalid address format: {address}")

    return host, int(port) if port else None


def readhttp(conn, packer):
    conn.settimeout(1)
    data = b''
    while b'\r\n\r\n' not in data:
        data += conn.recv(buffer_size)
        if len(data) == 0:
            raise Exception()
    buf = io.BytesIO(data)
    buf.readline()
    header = dpkt.http.parse_headers(buf)
    if 'content-length' in header:
        contentlen = int(header['content-length'])
        nowlen = len(buf.read())
        buf = io.BytesIO()
        buf.write(data)
        while contentlen - nowlen != 0:
            nowdata = conn.recv(contentlen - nowlen)
            tmplen = len(nowdata)
            if tmplen == 0:
                raise Exception()
            buf.write(nowdata)
            nowlen += tmplen
        data = buf.getvalue()
    
    while True:
        try:
            packer.unpack(data)
            break
        except dpkt.UnpackError:
            data += conn.recv(buffer_size)

    conn.settimeout(None)
    return data

with open(sys.argv[1], 'r') as f:
    config = yaml.load(f, Loader=yaml.FullLoader)

port = config['port']
usessl = config['usessl']
route = config['route']

lis = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
lis.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
if usessl:
    cert = config['cert']
    key = config['key']
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    lis = context.wrap_socket(lis, server_side=True)
lis.bind(('', port))
lis.listen(0)

print("start")

while True:
    try:
        clientdata = lis.accept()
        print(clientdata[1])
        with clientdata[0] as conn:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                init = False
                while True:
                    req = dpkt.http.Request()
                    data = readhttp(conn, req)
                    rule = {}
                    oldhost = req.headers['host']
                    if oldhost in route:
                        rule = route[oldhost]
                    elif 'default' in route:
                        rule = route['default']
                    if rule == None:
                        rule = {}
                    usehost = oldhost
                    if 'host' in rule:
                        usehost = rule['host']
                        if 'port' in rule:
                            usehost = f'{usehost}:{rule["port"]}'
                    useipdomain, useport = parse_ip_port(usehost)
                    print('%s %s %s/%s' % (req.method, req.uri, 'HTTP', req.version))
                    print(req.pack_hdr())
                    try:
                        print(req.body.decode("utf8"))
                    except:
                        print(req.body)
                    print()
                    if 'mode' not in rule or rule['mode'] == 'proxy':
                        if not init:
                            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                            if (rule['ssl'] if 'ssl' in rule else usessl):
                                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                                context.check_hostname = False
                                context.verify_mode = ssl.CERT_NONE
                                sock = context.wrap_socket(sock, server_hostname=useipdomain)
                                if useport == None:
                                    useport = 443
                            elif useport == None:
                                useport = 80
                            sock.connect((useipdomain, useport))
                            init = True
                        req.headers['host'] = usehost
                        sock.send(bytes(req))
                        res = dpkt.http.Response()
                        data = readhttp(sock, res)
                        if 'replace' in rule and rule['replace']:
                            body = res.body
                            if 'content-encoding' in res.headers and res.headers['content-encoding'] == 'gzip':
                                body = gzip.decompress(res.body)
                            body = body.replace(f'{"https" if "ssl" in rule and rule["ssl"] else "http"}://{usehost}'.encode(), f'{"https" if usessl else "http"}://{oldhost}'.encode())
                            body = body.replace(f'{"https" if "ssl" in rule and rule["ssl"] else "http"}:\\/\\/{usehost}'.encode(), f'{"https" if usessl else "http"}://{oldhost}'.encode())
                            for a in res.headers:
                                if type(res.headers[a]) == list:
                                    for b in range(len(res.headers[a])):
                                        res.headers[a][b] = res.headers[a][b].replace(f'{"https" if "ssl" in rule and rule["ssl"] else "http"}://{usehost}', f'{"https" if usessl else "http"}://{oldhost}')
                                else:
                                    res.headers[a] = res.headers[a].replace(f'{"https" if "ssl" in rule and rule["ssl"] else "http"}://{usehost}', f'{"https" if usessl else "http"}://{oldhost}')
                            res.body = body
                            if 'content-encoding' in res.headers and res.headers['content-encoding'] == 'gzip':
                                res.body = gzip.compress(body)
                            res.headers['content-length'] = len(res.body)
                            data = bytes(res)

                    else:
                        usecontent = 'HI'
                        if 'content' in rule:
                            usecontent = rule['content']
                        data = f"""HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\nContent-Length: {len(usecontent)}\r\n\r\n{usecontent}"""
                        data = data.encode('utf8')
                        res = dpkt.http.Response()
                        res.unpack(data)

                    print('%s/%s %s %s' % ('HTTP', res.version, res.status, res.reason))
                    print(res.pack_hdr())
                    try:
                        print(res.body.decode("utf8"))
                    except:
                        print(res.body)
                    print()

                    conn.send(data)
    except KeyboardInterrupt:
        exit()
    except Exception as e:
        print(e)
        pass

