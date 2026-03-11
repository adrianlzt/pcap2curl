#!/usr/bin/env python

import argparse
import re
from collections import defaultdict

from scapy.all import sniff, TCP, IP, Raw

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument("infile")
args = arg_parser.parse_args()

VALID_METHODS = {
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "CONNECT",
    "OPTIONS",
    "TRACE",
    "PATCH",
}


def is_http_request(data):
    if not data:
        return False
    try:
        text = data[:50].decode("utf-8", errors="ignore")
        return any(text.startswith(m + " ") for m in VALID_METHODS)
    except:
        return False


def is_tls_traffic(data):
    if not data or len(data) < 3:
        return False
    first_byte = data[0]
    return first_byte in (0x16, 0x14, 0x15, 0x17, 0x18)


def parse_http_request(data):
    try:
        text = data.decode("utf-8", errors="ignore")
    except:
        text = data.decode("latin-1", errors="ignore")

    lines = text.split("\r\n")
    if not lines:
        return None

    match = re.match(r"^([A-Z]+) ([^ ]+) HTTP/[\d.]+", lines[0])
    if not match:
        return None

    method = match.group(1)
    path = match.group(2)

    headers = {}
    body_start = 1
    for i, line in enumerate(lines[1:], 1):
        if line == "":
            body_start = i + 1
            break
        if ":" in line:
            key, val = line.split(":", 1)
            headers[key.strip()] = val.strip()

    body = "\r\n".join(lines[body_start:]) if body_start < len(lines) else None

    return {
        "method": method,
        "path": path,
        "headers": headers,
        "body": body if body else None,
    }


def http_to_curl(req):
    method = req["method"]
    path = req["path"]
    headers = req["headers"]
    body = req["body"]

    host = headers.get("Host", headers.get("host", "unknown"))
    url = f"http://{host}{path}"

    curl = f"curl '{url}' \\\n -X {method}"

    for name, value in headers.items():
        if name.lower() != "host":
            curl += f" \\\n -H '{name}: {value}'"

    if body:
        escaped_body = body.replace("'", "'\"'\"'")
        curl += f" \\\n -d '{escaped_body}'"

    return curl


def is_tls_connection(packets):
    for pkt in packets:
        if pkt.haslayer(TCP):
            if pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                return True
            if pkt.haslayer(Raw):
                if is_tls_traffic(pkt[Raw].load):
                    return True
    return False


def main():
    packets = sniff(offline=args.infile)

    connections = defaultdict(lambda: {"packets": [], "requests": []})

    for pkt in packets:
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            continue

        tcp = pkt[TCP]
        ip = pkt[IP]

        src_ip, src_port = ip.src, tcp.sport
        dst_ip, dst_port = ip.dst, tcp.dport

        conn_key = (src_ip, src_port, dst_ip, dst_port)
        reverse_key = (dst_ip, dst_port, src_ip, src_port)

        if conn_key in connections:
            connections[conn_key]["packets"].append(pkt)
        elif reverse_key in connections:
            connections[reverse_key]["packets"].append(pkt)
        else:
            connections[conn_key]["packets"].append(pkt)

    for key, conn in connections.items():
        stream_data = b""
        for pkt in sorted(
            conn["packets"], key=lambda p: p[TCP].seq if p[TCP].seq else 0
        ):
            if pkt.haslayer(Raw):
                stream_data += pkt[Raw].load

        pos = 0
        while pos < len(stream_data):
            req_start = None
            for m in VALID_METHODS:
                idx = stream_data.find(f"{m} ".encode(), pos)
                if idx != -1 and (req_start is None or idx < req_start):
                    req_start = idx

            if req_start is None:
                break

            end_markers = [b"\r\n\r\n", b"\n\n"]
            req_end = None
            for marker in end_markers:
                idx = stream_data.find(marker, req_start)
                if idx != -1 and (req_end is None or idx < req_end):
                    req_end = idx + len(marker)

            if req_end is None:
                break

            header_section = stream_data[req_start:req_end]
            parsed = parse_http_request(header_section)
            if parsed:
                content_length = 0
                for h in parsed["headers"]:
                    if h.lower() == "content-length":
                        try:
                            content_length = int(parsed["headers"][h])
                        except:
                            pass
                        break

                if content_length > 0 and req_end + content_length <= len(stream_data):
                    body_data = stream_data[req_end : req_end + content_length]
                    try:
                        parsed["body"] = body_data.decode("utf-8")
                    except:
                        parsed["body"] = body_data.decode("latin-1")
                    req_end += content_length

                conn["requests"].append(parsed)
                pos = req_end
            else:
                pos = req_start + 1

    valid_connections = []
    encrypted_indices = set()

    idx = 1
    for key, conn in connections.items():
        if not conn["requests"]:
            continue

        is_encrypted = is_tls_connection(conn["packets"])

        if is_encrypted:
            encrypted_indices.add(idx)

        valid_connections.append((key, conn, is_encrypted))
        idx += 1

    if not valid_connections:
        print("No HTTP connections found.")
        return

    print(f"Found {len(valid_connections)} HTTP connection(s):\n")

    for i, (key, conn, is_encrypted) in enumerate(valid_connections, 1):
        src_ip, src_port, dst_ip, dst_port = key
        num_requests = len(conn["requests"])

        if is_encrypted:
            print(
                f"[{i}] {src_ip}:{src_port} → {dst_ip}:{dst_port} (ENCRYPTED - {num_requests} request(s))"
            )
        else:
            print(
                f"[{i}] {src_ip}:{src_port} → {dst_ip}:{dst_port} ({num_requests} request(s))"
            )

        for req in conn["requests"]:
            print(f"    {req['method']} {req['path']}")
        print()

    user_input = input("Select connections (comma-separated, e.g., 1,3): ").strip()

    if user_input.lower() == "q":
        return

    try:
        selected = [int(x.strip()) for x in user_input.split(",")]
    except ValueError:
        print("Invalid selection.")
        return

    for sel in selected:
        if sel < 1 or sel > len(valid_connections):
            print(f"Invalid connection number: {sel}")
            continue
        if sel in encrypted_indices:
            print(f"Connection {sel} is encrypted, skipping.")
            continue

        key, conn, _ = valid_connections[sel - 1]
        print(f"\n# Connection {sel}: {key[0]}:{key[1]} → {key[2]}:{key[3]}\n")

        for req in conn["requests"]:
            curl = http_to_curl(req)
            print(curl)
            print()


if __name__ == "__main__":
    main()
