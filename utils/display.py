"""Display utilities for CyberRakshak."""


def banner(version):
    print(r"""
   ____      _               ____       _        _     _
  / ___|   _| |__   ___ _ __|  _ \ __ _| | _____| |__ | | ____ _
 | |  | | | | '_ \ / _ \ '__| |_) / _` | |/ / __| '_ \| |/ / _` |
 | |__| |_| | |_) |  __/ |  |  _ < (_| |   <\__ \ | | |   < (_| |
  \____\__, |_.__/ \___|_|  |_| \_\__,_|_|\_\___/_| |_|_|\_\__,_|
       |___/
    """)
    print(f"    Advanced Defensive Security Toolkit v{version}")
    print("    'Hacker se pehle - CyberRakshak!'\n")


def print_results(target, open_ports):
    if not open_ports:
        print(f"[*] No open ports found on {target}")
        return
    print(f"[*] Open ports on {target}:")
    print("-" * 40)
    for port in open_ports:
        print(f"    {port}/tcp  open")
    print("-" * 40)
    print(f"[*] Total: {len(open_ports)} open ports")
