# zcolors.py
# Shared terminal color helper used by all demo scripts

import time

RESET  = "\033[0m"
GREEN  = "\033[92m"
BLUE   = "\033[94m"
AMBER  = "\033[93m"
RED    = "\033[91m"
PURPLE = "\033[95m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"

def log(role, tag, msg, color=RESET):
    timestamp = time.strftime('%H:%M:%S')
    role_col  = BLUE if role == "SERVER" else GREEN
    print(f"{GRAY}[{timestamp}]{RESET} {role_col}{BOLD}[{role}]{RESET} {color}[{tag}]{RESET} {msg}")

def divider(label=""):
    line = "─" * 55
    if label:
        print(f"\n{CYAN}{BOLD}{'─'*20} {label} {'─'*20}{RESET}\n")
    else:
        print(f"{GRAY}{line}{RESET}")
