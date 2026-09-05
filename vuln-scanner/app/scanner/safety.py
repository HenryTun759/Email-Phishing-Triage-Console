import ipaddress
import socket

PRIVATE_OR_LOCAL = tuple(ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10"))
BLOCKED = tuple(ipaddress.ip_network(x) for x in ("0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4"))

def resolve_ipv4(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    addresses = {info[4][0] for info in infos}
    if len(addresses) != 1:
        raise ValueError("Host must resolve consistently to exactly one IPv4 address")
    return next(iter(addresses))

def is_allowed_host(host: str, allow_public: bool, authorized: bool) -> bool:
    ip = ipaddress.ip_address(resolve_ipv4(host))
    if any(ip in net for net in BLOCKED): return False
    if any(ip in net for net in PRIVATE_OR_LOCAL): return True
    return allow_public and authorized
