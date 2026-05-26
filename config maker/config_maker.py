#!/usr/bin/env python3
"""Config Maker

Rewrites proxy subscription entries by replacing the host:port portion in URLs
such as VLESS, VMess, Trojan, and Shadowsocks-style URIs.

Usage examples:
  python config_maker.py --config "vless://...@185.208.79.107:443?..."
  python config_maker.py --config-file input.txt --targets targets.txt
  python config_maker.py --config-file input.txt --targets "2.144.6.10:443,2.144.6.11:443"

The tool can read configs from a file or from direct input, and it can read
one or many target IP:port values from a file or from pasted text.
Each generated config keeps the original credentials, query string, and tag,
while replacing only the address host and port.
"""

from __future__ import annotations

import argparse
import random
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


URI_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "hy2://", "hysteria2://")
TARGET_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}$")
BOLD = "\033[1m"
RESET = "\033[0m"
DIM = "\033[2m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
SCRIPT_DIR = Path(__file__).resolve().parent


def color(text: str, code: str) -> str:
    return f"{code}{text}{RESET}"


def print_section(title: str, subtitle: str | None = None) -> None:
    print()
    print(f"{BOLD}{title}{RESET}")
    if subtitle:
        print(f"{DIM}{subtitle}{RESET}")


def print_kv(label: str, value: str) -> None:
    print(f"  {BOLD}{label}:{RESET} {value}")


def print_banner() -> None:
    print()
    print(color("╔════════════════════════════════════════════╗", CYAN))
    print(color("║       WHITEDNS CONFIG MAKER TOOL           ║", CYAN))
    print(color("╠════════════════════════════════════════════╣", CYAN))
    print(color("║  Rewrite configs or extract endpoints      ║", CYAN))
    print(color("║  from VLESS / VMess / Trojan / SS URIs    ║", CYAN))
    print(color("╚════════════════════════════════════════════╝", CYAN))
    print(f"{DIM}Folder:{RESET} {SCRIPT_DIR}")


def print_menu() -> None:
    print_section("Main Menu", "Choose a mode")
    print("  [1] Rewrite configs using new IP:port targets")
    print("  [2] Reverse extract IP:port from VLESS/config text")
    print("  [3] Reverse extract and save preview only")
    print("  [0] Exit")


def resolve_source_path(raw_path: str) -> Path | None:
    candidate = Path(raw_path.strip()).expanduser()
    if candidate.is_file():
        return candidate
    if not candidate.is_absolute():
        folder_candidate = SCRIPT_DIR / candidate
        if folder_candidate.is_file():
            return folder_candidate
    return None


def list_txt_files(folder: Path = SCRIPT_DIR) -> list[Path]:
    return sorted(
        [path for path in folder.iterdir() if path.is_file() and path.suffix.lower() == ".txt"],
        key=lambda path: path.name.lower(),
    )


def choose_txt_file(kind: str) -> str:
    files = list_txt_files()
    print_section(f"Select {kind} TXT file", f"Files in {SCRIPT_DIR}")
    if files:
        for index, file_path in enumerate(files, start=1):
            print(f"[{index}] {file_path.name}")
        print("[Enter] Use the first file")
    else:
        print("No TXT files found in this folder.")
    print("[0] Enter a custom path")
    choice = input("Select file number: ").strip()
    if files and choice == "":
        return files[0].read_text(encoding="utf-8", errors="ignore")
    if not files or choice == "0":
        raw_path = input("TXT file path: ").strip()
        if not raw_path:
            return ""
        selected = resolve_source_path(raw_path)
        if not selected:
            print(f"[!] File not found: {raw_path}")
            return ""
        return selected.read_text(encoding="utf-8", errors="ignore")
    try:
        selected_index = int(choice)
    except ValueError:
        print("[!] Invalid selection.")
        return ""
    if selected_index < 1 or selected_index > len(files):
        print("[!] Invalid selection.")
        return ""
    return files[selected_index - 1].read_text(encoding="utf-8", errors="ignore")


def choose_text_mode(prompt: str) -> str:
    print_section(prompt)
    print("  [1] Paste text")
    print("  [2] Choose TXT file from this folder")
    print("  [3] Enter TXT file path")
    choice = input("Select [1/2/3]: ").strip() or "1"
    if choice == "2":
        return choose_txt_file("source")
    if choice == "3":
        path = input("TXT file path: ").strip()
        if not path:
            return ""
        source_path = resolve_source_path(path)
        if not source_path:
            print(color(f"[!] File not found: {path}", RED))
            return ""
        return source_path.read_text(encoding="utf-8", errors="ignore")
    return prompt_text_block("Paste text below")


def read_text_source(value: str | None, file_path: str | None) -> str:
    if value:
        candidate = Path(value)
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8", errors="ignore")
        return value
    if file_path:
        return Path(file_path).read_text(encoding="utf-8", errors="ignore")
    data = sys.stdin.read()
    return data.strip()


def split_items(raw: str) -> list[str]:
    items: list[str] = []
    for part in re.split(r"[\s,;]+", raw.strip()):
        part = part.strip()
        if part:
            items.append(part)
    return items


def is_valid_target(target: str) -> bool:
    if not TARGET_RE.match(target):
        return False
    host, port_text = target.rsplit(":", 1)
    try:
        port = int(port_text)
    except ValueError:
        return False
    if port < 1 or port > 65535:
        return False
    octets = host.split(".")
    return all(0 <= int(octet) <= 255 for octet in octets)


def extract_hostport_from_uri(uri: str) -> str | None:
    parts = urlsplit(uri.strip())
    if not parts.scheme or not parts.netloc:
        return None
    hostport = parts.netloc.rsplit("@", 1)[-1].strip()
    if not hostport:
        return None
    return hostport


def normalize_target(target: str) -> str:
    target = target.strip()
    if not is_valid_target(target):
        raise ValueError(f"invalid target ip:port: {target}")
    return target


def extract_targets_from_text(raw: str) -> list[str]:
    seen: set[str] = set()
    targets: list[str] = []
    for token in split_items(raw):
        token = token.strip()
        if not token:
            continue
        if ":" in token and token.count(":") == 1 and is_valid_target(token):
            if token not in seen:
                targets.append(token)
                seen.add(token)
            continue
        if "://" in token:
            endpoint = extract_hostport_from_uri(token)
            if endpoint and is_valid_target(endpoint) and endpoint not in seen:
                targets.append(endpoint)
                seen.add(endpoint)
    return targets


def replace_endpoint(config_text: str, target: str) -> str:
    """Replace the authority endpoint in a URI-like proxy config."""
    config_text = config_text.strip()
    if not config_text:
        return config_text

    if "@" not in config_text or "://" not in config_text:
        return config_text

    parts = urlsplit(config_text)
    if not parts.scheme or not parts.netloc:
        return config_text

    if "@" in parts.netloc:
        userinfo, _old_hostport = parts.netloc.rsplit("@", 1)
        netloc = f"{userinfo}@{target}"
    else:
        netloc = target

    # Preserve path, query, fragment, username/password, and scheme.
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def rewrite_config_name(config_text: str, target: str) -> str:
    config_text = config_text.strip()
    if not config_text:
        return config_text
    if "#" in config_text:
        return re.sub(r"#.*$", f"#{target}", config_text)
    return f"{config_text}#{target}"


def extract_configs(raw: str) -> list[str]:
    raw = raw.strip()
    if not raw:
        return []

    lines: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if any(line.startswith(prefix) for prefix in URI_SCHEMES):
            lines.append(line)
            continue
        # If a file contains extra text, pick URI-like tokens from the line.
        tokens = re.findall(r"(?:vless|vmess|trojan|ss|hy2|hysteria2)://[^\s]+", line, flags=re.IGNORECASE)
        lines.extend(tokens)
    return lines


def normalize_config_lines(raw: str) -> list[str]:
    configs = extract_configs(raw)
    if configs:
        return configs
    raw = raw.strip()
    return [line.strip() for line in raw.splitlines() if line.strip()]


def load_configs(raw: str) -> list[str]:
    configs = extract_configs(raw)
    if configs:
        return configs
    # Treat a single pasted config as raw text if it was not split by lines.
    raw = raw.strip()
    return [raw] if raw else []


def build_output(configs: list[str], targets: list[str]) -> str:
    output_lines: list[str] = []
    for source in configs:
        for target in targets:
            rewritten = replace_endpoint(source, target)
            output_lines.append(rewritten)
    return "\n".join(output_lines) + ("\n" if output_lines else "")


def prompt_text_block(title: str) -> str:
    print_section(title, "Paste one item per line. Submit an empty line to finish.")
    lines: list[str] = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if not line.strip():
            break
        lines.append(line)
    return "\n".join(lines).strip()


def prompt_source(label: str, kind: str) -> str:
    print_section(label)
    print("[1] Paste text")
    print("[2] Choose TXT file from this folder")
    print("[3] Enter TXT file path")
    choice = input("Select [1/2/3]: ").strip() or "1"
    if choice == "2":
        return choose_txt_file(kind)
    if choice == "3":
        path = input("TXT file path: ").strip()
        if not path:
            return ""
        source_path = resolve_source_path(path)
        if not source_path:
            print(f"[!] File not found: {path}")
            return ""
        return source_path.read_text(encoding="utf-8", errors="ignore")
    if kind == "config":
        return prompt_text_block("Paste VLESS / proxy config lines")
    return prompt_text_block("Paste IP:PORT lines")


def extract_ips_from_config(raw: str) -> list[str]:
    """Extract ip:port endpoints from proxy config lines or arbitrary text.

    This function attempts to parse URI netlocs and also falls back to a
    simple regex extraction of IP:PORT tokens.
    """
    out: list[str] = []
    seen = set()

    # First try to parse url-like tokens
    for token in re.findall(r"(?:vless|vmess|trojan|ss|hy2|hysteria2)://[^\s]+", raw, flags=re.IGNORECASE):
        try:
            hostport = extract_hostport_from_uri(token)
            if hostport and hostport not in seen:
                try:
                    normalize_target(hostport)
                    out.append(hostport)
                    seen.add(hostport)
                except Exception:
                    pass
        except Exception:
            continue

    # Fallback: find any ip:port tokens in text
    for token in re.findall(r"(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}", raw):
        if token not in seen:
            try:
                normalize_target(token)
                out.append(token)
                seen.add(token)
            except Exception:
                pass

    return out


def save_text_output(output_path: Path, lines: list[str]) -> Path:
    if not output_path.is_absolute():
        output_path = SCRIPT_DIR / output_path
    if output_path.suffix.lower() != ".txt":
        output_path = output_path.with_suffix(".txt")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output_path


def assign_samples_to_targets(configs: list[str], targets: list[str]) -> list[tuple[str, str]]:
    if not configs or not targets:
        return []

    shuffled_pool = configs[:]
    random.shuffle(shuffled_pool)

    assignments: list[tuple[str, str]] = []
    for target in targets:
        if not shuffled_pool:
            shuffled_pool = configs[:]
            random.shuffle(shuffled_pool)
        source = shuffled_pool.pop()
        assignments.append((source, target))
    return assignments


def rewrite_configs(configs: list[str], targets: list[str], append_tag: bool) -> list[str]:
    rewritten_blocks: list[str] = []
    for source, target in assign_samples_to_targets(configs, targets):
        rewritten = replace_endpoint(source, target)
        rewritten = rewrite_config_name(rewritten, target)
        rewritten_blocks.append(rewritten)
    return rewritten_blocks


def interactive_run() -> int:
    print_banner()
    while True:
        print_menu()
        choice = input("Select an option: ").strip()
        if choice in {"0", "q", "quit", "exit"}:
            print(color("Goodbye.", DIM))
            return 0
        if choice == "1":
            return rewrite_workflow()
        if choice == "2":
            return reverse_workflow(save_result=True)
        if choice == "3":
            return reverse_workflow(save_result=False)
        print(color("[!] Invalid choice. Please select 1, 2, 3, or 0.", RED))


def interactive_run_reverse() -> int:
    return reverse_workflow(save_result=True)


def rewrite_workflow() -> int:
    print_section("Rewrite Mode", "Replace the endpoint in each proxy config with new IP:port values.")
    raw_configs = choose_text_mode("Load configs")
    raw_targets = choose_text_mode("Load target IP:port values")

    configs = normalize_config_lines(raw_configs)
    targets = extract_targets_from_text(raw_targets)

    if not configs:
        print(color("[!] No configs found.", RED))
        return 1
    if not targets:
        print(color("[!] No valid IP:port targets found.", RED))
        return 1

    output_default = SCRIPT_DIR / "rewritten_configs.txt"
    output_file = input(f"\nOutput TXT file [{output_default}]: ").strip() or str(output_default)
    output_path = save_text_output(Path(output_file), rewrite_configs(configs, targets, True))

    print_section("Output summary")
    print_kv("Configs loaded", str(len(configs)))
    print_kv("Targets loaded", str(len(targets)))
    print_kv("Saved", str(output_path))
    preview_count = min(3, len(targets))
    if preview_count:
        print()
        print("Preview:")
        for target in targets[:preview_count]:
            print(f"- {target}")
    return 0


def reverse_workflow(save_result: bool) -> int:
    print_section("Reverse Mode", "Extract IP:port endpoints from VLESS and other proxy configs.")
    raw_configs = choose_text_mode("Load config text")
    if not raw_configs.strip():
        print(color("[!] No input provided.", RED))
        return 1

    ips = extract_ips_from_config(raw_configs)
    if not ips:
        print(color("[!] No IP:PORT endpoints found in the supplied config.", RED))
        return 1

    output_path = None
    if save_result:
        output_default = SCRIPT_DIR / "extracted_ips.txt"
        output_file = input(f"\nOutput TXT file [{output_default}]: ").strip() or str(output_default)
        output_path = save_text_output(Path(output_file), ips)

    print_section("Output summary")
    print_kv("Endpoints found", str(len(ips)))
    if output_path:
        print_kv("Saved", str(output_path))
    preview_count = min(6, len(ips))
    if preview_count:
        print()
        print("Preview:")
        for item in ips[:preview_count]:
            print(f"- {item}")
        if len(ips) > preview_count:
            print(f"- ... {len(ips) - preview_count} more")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Rewrite proxy configs with new IP:port values.")
    parser.add_argument("--config", help="Direct config text to rewrite, or a TXT file path.")
    parser.add_argument("--config-file", help="Path to a TXT file containing one or more configs.")
    parser.add_argument("--targets", help="Targets as comma/space/newline separated ip:port values, or a TXT file path.")
    parser.add_argument("--targets-file", help="Path to a TXT file containing target ip:port values.")
    parser.add_argument("--output", help="Output file path. Defaults to rewritten_configs.txt in the current folder.")
    parser.add_argument("--append-target-tag", action="store_true", help="Kept for compatibility; the config name is always rewritten to the target ip:port.")
    parser.add_argument("--reverse", action="store_true", help="Extract IP:port endpoints from provided configs/text instead of rewriting configs.")
    args = parser.parse_args()

    if len(sys.argv) == 1:
        return interactive_run()

    # interactive reverse mode
    if args.reverse and len(sys.argv) == 2:
        return interactive_run_reverse()

    if args.reverse:
        raw_configs = read_text_source(args.config, args.config_file)
        ips = extract_ips_from_config(raw_configs)
        if not ips:
            print("No endpoints found.", file=sys.stderr)
            return 1
        output_path = Path(args.output) if args.output else SCRIPT_DIR / "extracted_ips.txt"
        if not output_path.is_absolute():
            output_path = SCRIPT_DIR / output_path
        if output_path.suffix.lower() != ".txt":
            output_path = output_path.with_suffix(".txt")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("\n".join(ips) + "\n", encoding="utf-8")
        print(f"Wrote {len(ips)} endpoints to {output_path}")
        return 0

    raw_configs = read_text_source(args.config, args.config_file)
    raw_targets = read_text_source(args.targets, args.targets_file)

    configs = load_configs(raw_configs)
    targets = [normalize_target(item) for item in split_items(raw_targets)]

    if not configs:
        print("No configs found.", file=sys.stderr)
        return 1
    if not targets:
        print("No targets found.", file=sys.stderr)
        return 1

    output_path = Path(args.output) if args.output else SCRIPT_DIR / "rewritten_configs.txt"
    if not output_path.is_absolute():
        output_path = SCRIPT_DIR / output_path
    if output_path.suffix.lower() != ".txt":
        output_path = output_path.with_suffix(".txt")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rewritten_blocks = rewrite_configs(configs, targets, True)

    output_path.write_text("\n".join(rewritten_blocks) + "\n", encoding="utf-8")

    print(f"Loaded {len(configs)} config(s)")
    print(f"Loaded {len(targets)} target(s)")
    print(f"Wrote {len(rewritten_blocks)} rewritten config(s) to {output_path}")
    preview_count = min(3, len(rewritten_blocks))
    if preview_count:
        print("Preview:")
        for item in rewritten_blocks[:preview_count]:
            print(f"- {item}")
        if len(rewritten_blocks) > preview_count:
            print(f"- ... {len(rewritten_blocks) - preview_count} more")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
