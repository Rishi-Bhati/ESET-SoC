#!/usr/bin/env python3
import socket
import argparse
import json
import time

def send_udp(host: str, port: int, message: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message.encode("utf-8"), (host, port))
    sock.close()
    print(f"Sent UDP syslog message to {host}:{port}")

def send_tcp(host: str, port: int, message: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
        # Add newline delimiter for streaming syslog TCP readers
        sock.sendall((message + "\n").encode("utf-8"))
        print(f"Sent TCP syslog message to {host}:{port}")
    except ConnectionRefusedError:
        print(f"Error: Connection refused by TCP server at {host}:{port}. Is it running?")
    finally:
        sock.close()

def main() -> None:
    parser = argparse.ArgumentParser(description="Helper to simulate ESET Syslog JSON exports.")
    parser.add_argument("--host", default="127.0.0.1", help="Syslog host")
    parser.add_argument("--udp-port", type=int, default=514, help="Syslog UDP port")
    parser.add_argument("--tcp-port", type=int, default=601, help="Syslog TCP port")
    parser.add_argument("--protocol", choices=["udp", "tcp"], default="udp", help="Connection protocol")
    parser.add_argument("--severity", default="HIGH", help="Alert severity (LOW, MEDIUM, HIGH, CRITICAL)")
    args = parser.parse_args()
    
    # ESET JSON format payload representation
    payload = {
        "event": "Threat Detection",
        "id": f"syslog-sim-{int(time.time())}",
        "uuid": "e9b724fa-774f-4d69-a1b9-syslogsim12",
        "computer_uuid": "c3d5f6a7-8e9f-0a1b-syslogsim34",
        "time": "2026-08-10T12:00:00Z",
        "severity": args.severity,
        "threat_name": "Win32/HackTool.Mimikatz.B",
        "computer_name": "SYSLOG-TARGET-PC",
        "username": "local.admin",
        "os": "Windows Server 2022",
        "action": "Blocked",
        "handled": False,
        "hash": "b2f6ef8023abc456def89123456abcdef7890123456abcdef7890123456abcde",
        "ip": "198.51.100.22",
        "subject": f"Syslog Sim: {args.severity} detection",
        "content": "Mimikatz tool was detected and blocked on domain infrastructure."
    }
    
    # standard RFC 5424 framing format containing the JSON payload
    syslog_msg = f"<14>1 2026-08-10T12:00:00Z local-host ESET-PROTECT - - - {json.dumps(payload)}"
    
    if args.protocol == "udp":
        send_udp(args.host, args.udp_port, syslog_msg)
    else:
        send_tcp(args.host, args.tcp_port, syslog_msg)

if __name__ == "__main__":
    main()
