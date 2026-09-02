import ipaddress
import socket


def reverse_dns_lookup(ip: str) -> dict:
    result = {
        "ip": ip,
        "available": False,
        "hostname": None,
        "error": None,
    }

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        result["error"] = "Invalid IP address."
        return result

    if not address.is_global:
        result["error"] = "Reverse DNS skipped for non-public IP address."
        return result

    try:
        hostname, _, _ = socket.gethostbyaddr(ip)

        result["available"] = True
        result["hostname"] = hostname

    except socket.herror:
        result["error"] = "No PTR record found."

    except socket.gaierror:
        result["error"] = "Reverse DNS lookup failed."

    except Exception as error:
        result["error"] = str(error)

    return result