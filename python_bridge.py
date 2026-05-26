#!/usr/bin/env python3
import argparse
import asyncio
import os
import sys


def _bootstrap_parent_path():
    here = os.path.abspath(os.path.dirname(__file__))
    root = os.path.abspath(os.path.join(here, ".."))
    if root not in sys.path:
        sys.path.insert(0, root)


def _init_base():
    import utils.config as config
    import utils.asn_engine as asn_engine
    from utils.route_service import ROUTE_SERVICE

    config.load_config()
    ROUTE_SERVICE.load_ip_pool()
    ROUTE_SERVICE.load_banned_routes()
    asn_engine.load_asn_data()


def _execute_core(module):
    if hasattr(module, "run"):
        asyncio.run(module.run())
        return
    if hasattr(module, "main"):
        if asyncio.iscoroutinefunction(module.main):
            asyncio.run(module.main())
        else:
            module.main()
        return
    raise RuntimeError("Selected core has no run/main entrypoint")


def _run_action(action):
    import utils.config as config
    from utils.app_service import APP_SERVICE

    if action == "scan_menu":
        import cores.ui_scan as ui_scan
        ui_scan.menu_scan()
    elif action == "manage_pool":
        import cores.ui_scan as ui_scan
        ui_scan.menu_manage_pool()
    elif action == "instant_connect":
        import cores.ui_scan as ui_scan
        ui_scan.menu_instant_connect()
    elif action == "reroute_domain":
        import cores.ui_tools as ui_tools
        ui_tools.menu_reroute_domain()
    elif action == "inspect_ips":
        import cores.ui_tools as ui_tools
        ui_tools.menu_inspect_ips()
    elif action == "autotune":
        import cores.autotuner as autotuner_core
        _execute_core(autotuner_core)
    elif action == "manage_route_rules":
        import cores.ui_tools as ui_tools
        ui_tools.menu_manage_route_rules()
    elif action == "install_mmdf_ca":
        import cores.ui_tools as ui_tools
        ui_tools.menu_install_mmdf_ca()
    elif action == "socks5_scanner":
        import cores.socks5_scanner as socks5_core
        _execute_core(socks5_core)
    elif action == "http_scanner":
        import cores.http_scanner as http_core
        _execute_core(http_core)
    elif action == "desync_strategies":
        import cores.ui_dpi as ui_dpi
        ui_dpi.menu_manage_dpi_strategies()
    elif action == "select_dpi_target":
        import cores.ui_dpi as ui_dpi
        pairs = ui_dpi.load_desync_pairs()
        if pairs:
            ui_dpi.prompt_dpi_target_from_pairs(pairs)
        else:
            ui_dpi.prompt_manual_dpi_target()
    elif action == "desync_scanner":
        import cores.desync_scanner as desync_core
        _execute_core(desync_core)
    elif action == "sni_scanner":
        import cores.sni_scanner as sni_core
        _execute_core(sni_core)
    elif action == "config_maker":
        # Execute the standalone config maker script (resides in 'config maker' folder)
        import runpy
        here = os.path.abspath(os.path.dirname(__file__))
        script_path = os.path.join(here, "..", "config maker", "config_maker.py")
        script_path = os.path.abspath(script_path)
        if not os.path.exists(script_path):
            print(f"Config maker script not found: {script_path}")
            return
        runpy.run_path(script_path, run_name="__main__")
    elif action == "start_white_proxy":
        APP_SERVICE.set_connection_mode("white_ip", persist=True)
        import cores.white_core as proxy_core
        _execute_core(proxy_core)
    elif action == "start_dpi_proxy":
        APP_SERVICE.set_connection_mode("dpi_desync", persist=True)
        import cores.white_core as proxy_core
        _execute_core(proxy_core)
    elif action == "start_mixed_proxy":
        APP_SERVICE.set_connection_mode("mixed", persist=True)
        import cores.white_core as proxy_core
        _execute_core(proxy_core)
    elif action == "clear_route_cache":
        ok = APP_SERVICE.clear_route_cache()
        print("[+] Cache cleared successfully." if ok else "[-] Cache already empty.")
    elif action == "set_proxy_port":
        raw = input(f"Enter new port (Current {config.PROXY_PORT}): ").strip()
        if raw.isdigit() and 1 <= int(raw) <= 65535:
            APP_SERVICE.set_proxy_port(int(raw))
            print(f"[+] Proxy port updated to {int(raw)}")
        else:
            print("[-] Invalid port number.")
    else:
        raise ValueError(f"Unknown action: {action}")


def main():
    parser = argparse.ArgumentParser(description="Go<->Python compatibility bridge")
    parser.add_argument("--action", required=True)
    args = parser.parse_args()

    _bootstrap_parent_path()
    _init_base()
    _run_action(args.action)


if __name__ == "__main__":
    main()
