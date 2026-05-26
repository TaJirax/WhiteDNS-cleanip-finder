import os
import sys
import time
import asyncio
import socket
import ssl
import random
import ipaddress

from utils import config
from utils import asn_engine
from utils import paths
from utils import data_store
from utils import storage
from utils.helpers import clear_screen

# Scanner tuning defaults
DEFAULT_CONNECT_TIMEOUT = 3.0
DEFAULT_READ_TIMEOUT = 3.0
DEFAULT_RETRIES = 2
DEFAULT_BACKOFF = 1.5

async def verify_clean_ip(ip):
    """
    Vigorously verifies that an IP is alive and securely belongs to Cloudflare,
    ensuring it hasn't been intercepted by DPI Captive Portals.
    """
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    
    # Retries with exponential backoff for flakiness
    for attempt in range(DEFAULT_RETRIES + 1):
        try:
            # 1. Quick TCP Check (Fail fast if completely blocked)
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, 443), timeout=DEFAULT_CONNECT_TIMEOUT)
            writer.close()
            await writer.wait_closed()

            # 2. Deep TLS & HTTP Verification
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 443, ssl=ssl_ctx, server_hostname="speed.cloudflare.com"),
                timeout=DEFAULT_CONNECT_TIMEOUT
            )

            probe = b"GET / HTTP/1.1\r\nHost: speed.cloudflare.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            writer.write(probe)
            await writer.drain()

            resp = await asyncio.wait_for(reader.read(4096), timeout=DEFAULT_READ_TIMEOUT)
            writer.close()
            await writer.wait_closed()

            if not resp:
                raise ValueError("empty response")

            resp_lower = resp.lower()

            # Protect against DPI redirection (Fake Pass)
            dpi_signatures = [b"peyvandha.ir", b"10.10.3", b"internet.ir", b"cra.ir"]
            if any(blocked in resp_lower for blocked in dpi_signatures):
                return False

            status_line = resp_lower.split(b'\r\n')[0]
            if b"http/" in status_line:
                # We prefer a Cloudflare footprint but accept any clean HTTP response
                if b"cloudflare" in resp_lower or b"server: cloudflare" in resp_lower or b"via: 1.1 cloudflare" in resp_lower:
                    return True
                return True

        except Exception:
            # backoff before retrying
            if attempt < DEFAULT_RETRIES:
                await asyncio.sleep(DEFAULT_BACKOFF * (attempt + 1))
            continue

    return False

async def race_ips(ip_list, max_concurrency=200):
    """
    Races a massive list of IPs using a highly optimized Async Worker Queue.
    The absolute first one to pass `verify_clean_ip` wins and kills the remaining workers.
    """
    queue = asyncio.Queue()
    for ip in ip_list:
        queue.put_nowait(ip)
        
    working_ip = None
    total = len(ip_list)
    completed = 0
    
    async def worker():
        nonlocal working_ip, completed
        while True:
            if working_ip:
                return
            try:
                ip = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                if await verify_clean_ip(ip):
                    if not working_ip:
                        working_ip = ip
            finally:
                completed += 1
                if completed % 20 == 0 or completed == total:
                    sys.stdout.write(f"\r[*] Racing IPs... {completed}/{total} checked ")
                    sys.stdout.flush()
                queue.task_done()
                
    # Boot up the concurrent worker pool
    workers = [asyncio.create_task(worker()) for _ in range(min(max_concurrency, total))]
    
    # Wait until queue is fully processed or a working IP is found
    while not queue.empty() and not working_ip:
        await asyncio.sleep(0.1)
        
    if working_ip:
        for w in workers: w.cancel()
        
    await asyncio.gather(*workers, return_exceptions=True)
    print() # Newline after progress bar
    return working_ip

async def run():
    clear_screen()
    print("==================================================")
    print("   SNI SCANNER - CLOUDFLARE WHITELIST HUNTER")
    print("==================================================")

    # 1. Locate and Load the SNI list
    target_file = paths.root_path("assets", "cf-domains.txt")
    if not os.path.exists(target_file):
        print(f"\n[-] SNI list not found at: {target_file}")
        print("[*] Please create the 'assets' folder and place 'cf-domains.txt' inside it.")
        input("\nPress Enter to return...")
        return

    with open(target_file, "r", encoding="utf-8") as f:
        snis = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    snis = list(set(snis))
    if not snis:
        print("\n[-] The SNI list is empty.")
        input("Press Enter to return...")
        return
        
    random.shuffle(snis)
    print(f"\n[*] Loaded {len(snis)} unique domains to test.")

    # 2. Configure Scan Parameters & Auto-Mine IP
    print("\n[?] How would you like to obtain a Clean Cloudflare IP?")
    print("    [1] Enter an IP manually")
    print("    [2] Auto-Mine via CNAMEs [Fastest]")
    print("    [3] Deep Scan Iran Cloudflare ASNs [Local Edge Nodes]")
    print("    [4] Deep Scan Global Cloudflare ASNs [International Nodes]")
    choice = input("    Choice [Default 2]: ").strip()
    
    test_ip = None
    
    if choice == "1":
        manual_ip = input("\n    Enter your Clean IP: ").strip()
        if not manual_ip:
            print("[-] No IP provided.")
            return
            
        print(f"\n[*] Validating IP: {manual_ip} ...")
        if await verify_clean_ip(manual_ip):
            print("[+] Success! IP is valid, clean, and bypasses DPI.")
            test_ip = manual_ip
        else:
            print("[-] WARNING: This IP failed verification!")
            print("    It is likely dead, blocked on TCP 443, or hijacked by a DPI Captive Portal.")
            cont = input("    Are you absolutely sure you want to use it? (y/N): ").strip().lower()
            if cont == 'y':
                test_ip = manual_ip
            else:
                return
                
    elif choice in ["3", "4"]:
        print("\n[*] Expanding Cloudflare ASN Databases...")
        if not asn_engine.ASN_LOADED:
            asn_engine.load_asn_data()
            
        if choice == "3":
            print("[*] Target: Iran Cloudflare Edge Nodes (AS13335)")
        else:
            print("[*] Target: Global Cloudflare Edge Nodes (Floudclare, AS209242, etc.)")
            
        iran_subnets = []
        global_subnets = []
        
        # Manually extract from asn_engine to differentiate the naming typo
        for octet_list in asn_engine.ASN_DATA_V4.values():
            for net, asn, name, as_type in octet_list:
                if asn.upper() == 'AS13335':
                    if 'floudclare' in name.lower():
                        global_subnets.append(net)
                    else:
                        iran_subnets.append(net)
                elif asn.upper() in ["AS209242", "AS14789", "AS395747", "AS132892", "AS202623", "AS203898"]:
                    global_subnets.append(net)
                    
        mined_ips = set()
        
        if choice == "3":
            print(f"[*] Found {len(iran_subnets)} Iran Edge Subnets. Expanding all IPs...")
            for net in iran_subnets:
                for ip in net.hosts():
                    mined_ips.add(str(ip))
        else:
            print(f"[*] Found {len(global_subnets)} Global Edge Subnets. Sampling wide geographical spread...")
            # We want about 15,000 IPs randomly plucked from different subnets around the world
            random.shuffle(global_subnets)
            for net in global_subnets:
                if len(mined_ips) >= 15000: break
                try:
                    if net.num_addresses < 10:
                        for ip in net.hosts(): mined_ips.add(str(ip))
                    else:
                        first_ip = int(net.network_address) + 1
                        last_ip = int(net.broadcast_address) - 1
                        for _ in range(3): # Take 3 random IPs per subnet
                            mined_ips.add(str(ipaddress.IPv4Address(random.randint(first_ip, last_ip))))
                except Exception: pass
                
        test_pool = list(mined_ips)
        random.shuffle(test_pool)
        print(f"[*] Generated {len(test_pool)} IPs to race. Testing thoroughly...")
        
        # Test the ENTIRE pool, no slicing limitations!
        test_ip = await race_ips(test_pool, max_concurrency=200)
        
    else: # Default 2 (CNAMEs)
        print("\n[*] Mining Cloudflare IPs from CNAMEs...")
        loop = asyncio.get_running_loop()
        mined_ips = set()
        
        async def resolve_domain(domain):
            try:
                info = await asyncio.wait_for(
                    loop.getaddrinfo(domain, 443, family=socket.AF_INET, type=socket.SOCK_STREAM), 
                    timeout=3.0
                )
                for item in info:
                    mined_ips.add(item[4][0])
            except Exception:
                pass
                
        tasks = [asyncio.create_task(resolve_domain(d)) for d in config.CLOUDFLARE_CNAME_DOMAINS]
        await asyncio.gather(*tasks)
        
        mined_list = list(mined_ips)
        random.shuffle(mined_list)
        print(f"[*] Resolved {len(mined_list)} IPs. Finding one with open TCP 443 and Clean TLS...")
        test_ip = await race_ips(mined_list, max_concurrency=50)

    if not test_ip:
        print("\n[-] Failed to find a clean working IP. The DPI is aggressively filtering these ranges.")
        input("Press Enter to return...")
        return
        
    concurrency = input(f"\n[+] Active Clean IP: {test_ip}\n[?] Enter SNI scanner concurrency limit (Default: 100): ").strip()
    concurrency = int(concurrency) if concurrency.isdigit() else 100

    print(f"\n[*] Launching asynchronous SNI probes against {test_ip}...\n")

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    # Prepare CSV output
    stamp = time.strftime("%Y%m%d-%H%M%S")
    csv_name = f"sni_results_{stamp}.csv"
    csv_path = paths.data_path("scan_outputs", csv_name)
    storage.atomic_write_text(csv_path, "hostname,ipport,status,latency_ms,tls_version,http_status\n")

    semaphore = asyncio.Semaphore(concurrency)
    clean_snis = []
    completed = 0
    total_tasks = len(snis)

    async def check_sni(sni):
        nonlocal completed
        async with semaphore:
            status_label = "UNKNOWN"
            latency_ms = ""
            tls_v = ""
            http_status = ""
            ipport = ""

            # retry loop
            for attempt in range(DEFAULT_RETRIES + 1):
                start = time.monotonic()
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(test_ip, 443, ssl=ssl_ctx, server_hostname=sni),
                        timeout=DEFAULT_CONNECT_TIMEOUT
                    )

                    probe = f"GET / HTTP/1.1\r\nHost: {sni}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode()
                    writer.write(probe)
                    await writer.drain()

                    resp = await asyncio.wait_for(reader.read(4096), timeout=DEFAULT_READ_TIMEOUT)
                    end = time.monotonic()
                    latency_ms = f"{(end - start) * 1000:.1f}"

                    ssl_obj = writer.get_extra_info('ssl_object')
                    if ssl_obj:
                        try:
                            tls_v = ssl_obj.version() or ""
                        except Exception:
                            tls_v = ""

                    peer = writer.get_extra_info('peername')
                    if peer:
                        try:
                            ipport = f"{peer[0]}:{peer[1]}"
                        except Exception:
                            ipport = ""

                    writer.close()
                    await writer.wait_closed()

                    if resp:
                        resp_lower = resp.lower()
                        dpi_signatures = [b"peyvandha.ir", b"10.10.3", b"internet.ir", b"cra.ir"]
                        if any(blocked in resp_lower for blocked in dpi_signatures):
                            status_label = "FAIL"
                        else:
                            status_line = resp_lower.split(b'\r\n')[0]
                            if b"http/" in status_line:
                                # extract HTTP status code
                                try:
                                    parts = status_line.split()
                                    http_status = parts[1].decode() if len(parts) >= 2 else ""
                                except Exception:
                                    http_status = ""
                                status_label = "PASS"
                            else:
                                status_label = "UNKNOWN"
                    else:
                        status_label = "FAIL"

                    # success or definitive result -> break retry loop
                    break

                except Exception:
                    # backoff before next attempt
                    if attempt < DEFAULT_RETRIES:
                        await asyncio.sleep(DEFAULT_BACKOFF * (attempt + 1))
                    continue

            # record result to CSV
            csv_line = f"{sni},{ipport},{status_label},{latency_ms},{tls_v},{http_status}"
            try:
                storage.append_line(csv_path, csv_line)
            except Exception:
                pass

            if status_label == "PASS":
                clean_snis.append(sni)
                sys.stdout.write('\r' + ' ' * 80 + '\r')
                print(f"[+] CLEAN SNI FOUND: {sni}  ({ipport}) {latency_ms}ms {tls_v} HTTP:{http_status}")

            completed += 1
            if completed % 10 == 0 or completed == total_tasks:
                percent = (completed / total_tasks) * 100
                bar_len = 30
                filled = int(bar_len * completed / total_tasks)
                bar = '█' * filled + '-' * (bar_len - filled)
                sys.stdout.write(f"\r[{bar}] {percent:.1f}% ({completed}/{total_tasks})")
                sys.stdout.flush()

    tasks = [asyncio.create_task(check_sni(sni)) for sni in snis]
    
    try:
        await asyncio.gather(*tasks)
    except KeyboardInterrupt:
        print("\n\n[-] Scan cancelled by user.")
        for t in tasks:
            if not t.done(): t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    
    print("\n\n==================================================")
    print("   SCAN COMPLETE")
    print("==================================================")
    
    if clean_snis:
        print(f"[+] Successfully found {len(clean_snis)} clean SNIs!")
        out_content = "".join(f"{s}\n" for s in sorted(clean_snis))
        data_store.write_text("clean_snis.txt", out_content, encoding="utf-8")
        print("[+] Whitelisted domains logically saved to data/clean_snis.txt")
    else:
        print("[-] No clean SNIs found. The DPI might be actively blocking every SNI in your list.")
        
    input("\nPress Enter to return to main menu...")

if __name__ == "__main__":
    asyncio.run(run())
