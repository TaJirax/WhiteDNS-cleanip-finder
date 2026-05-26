#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
from urllib.parse import urlparse, urlunparse

BANNER = r"""
██╗    ██╗██╗  ██╗██╗████████╗███████╗██████╗ ███╗   ██╗███████╗
██║    ██║██║  ██║██║╚══██╔══╝██╔════╝██╔══██╗████╗  ██║██╔════╝
██║ █╗ ██║███████║██║   ██║   █████╗  ██║  ██║██╔██╗ ██║███████╗
██║███╗██║██╔══██║██║   ██║   ██╔══╝  ██║  ██║██║╚██╗██║╚════██║
╚███╔███╔╝██║  ██║██║   ██║   ███████╗██████╔╝██║ ╚████║███████║
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝   ╚═╝   ╚══════╝╚═════╝ ╚═╝  ╚═══╝╚══════╝

                WHITEDNS VLESS IP:PORT REPLACER
"""

VLESS_REGEX = re.compile(r"^vless://", re.IGNORECASE)


def replace_ip_port(vless_config, new_ip_port):
    try:
        parsed = urlparse(vless_config)

        # Extract host and port
        if ":" not in new_ip_port:
            print(f"[!] Invalid IP:PORT -> {new_ip_port}")
            return None

        ip, port = new_ip_port.strip().split(":")

        # Replace netloc
        auth = parsed.netloc.split("@")[0]

        new_netloc = f"{auth}@{ip}:{port}"

        new_url = urlunparse((
            parsed.scheme,
            new_netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))

        return new_url

    except Exception as e:
        print(f"[!] Error processing config: {e}")
        return None


def load_lines_from_file(path):
    if not os.path.isfile(path):
        print("[!] File not found.")
        return []

    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def get_vless_configs():
    choice = input(
        "\n[1] Enter VLESS manually\n"
        "[2] Load VLESS from txt file\n"
        "Choice: "
    ).strip()

    if choice == "1":
        print("\nPaste VLESS configs (empty line to finish):")
        configs = []

        while True:
            line = input().strip()
            if not line:
                break

            if VLESS_REGEX.match(line):
                configs.append(line)

        return configs

    elif choice == "2":
        path = input("TXT file path: ").strip()
        return [
            line for line in load_lines_from_file(path)
            if VLESS_REGEX.match(line)
        ]

    else:
        print("[!] Invalid choice.")
        return []


def get_ip_ports():
    choice = input(
        "\n[1] Enter IP:PORT manually\n"
        "[2] Load IP:PORT from txt file\n"
        "Choice: "
    ).strip()

    if choice == "1":
        print("\nPaste IP:PORT values (empty line to finish):")
        ips = []

        while True:
            line = input().strip()
            if not line:
                break

            ips.append(line)

        return ips

    elif choice == "2":
        path = input("TXT file path: ").strip()
        return load_lines_from_file(path)

    else:
        print("[!] Invalid choice.")
        return []


def main():
    os.system("cls" if os.name == "nt" else "clear")
    print(BANNER)

    configs = get_vless_configs()

    if not configs:
        print("[!] No VLESS configs loaded.")
        return

    ip_ports = get_ip_ports()

    if not ip_ports:
        print("[!] No IP:PORT values loaded.")
        return

    output_configs = []

    for config in configs:
        for ip_port in ip_ports:
            new_config = replace_ip_port(config, ip_port)

            if new_config:
                output_configs.append(new_config)

    if not output_configs:
        print("[!] Nothing generated.")
        return

    print("\n========== GENERATED CONFIGS ==========\n")

    for cfg in output_configs:
        print(cfg)
        print()

    save = input("\nSave output to file? (y/n): ").strip().lower()

    if save == "y":
        output_file = "generated_vless.txt"

        with open(output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(output_configs))

        print(f"[+] Saved to {output_file}")


if __name__ == "__main__":
    main()