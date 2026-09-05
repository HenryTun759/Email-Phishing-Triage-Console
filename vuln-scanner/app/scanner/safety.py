import ipaddress
import socket

PRIVATE_OR_LOCAL = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"), ipaddress.ip_network("192.168.0.0/16"), ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("169.254.0.0/16"))

def resolve_ipv4(host: str) -> str:
    infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    if not infos:
        raise ValueError("Host did not resolve to IPv4")
    return infos[0][4][0]

def is_allowed_host(host: str, allow_public: bool, authorized: bool) -> bool:
    ip = ipaddress.ip_address(resolve_ipv4(host))
    if any(ip in net for net in PRIVATE_OR_LOCAL):
        return True
    return allow_public and authorized
