RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"
BOLD = "\033[1m"
BLUE = "\033[34m"
YELLOW = "\033[1;33m"
MAGENTA = "\033[35m"
BRIGHT_MAGENTA = "\033[95m"
CYAN = "\033[96m"
ORANGE = "\033[33m"

def print_error(msg):
    print(f"{RED}[ERROR] {msg}{RESET}")

def print_success(msg):
    print(f"{BOLD}{GREEN}[SUCCESS] {msg}{RESET}")

def print_info(msg):
    print(f"\n{BOLD}{BLUE}[INFO] {msg}{RESET}")

def print_process(msg):
    print(f"{BOLD}{BRIGHT_MAGENTA}[PROCESS] {msg}{RESET}")

def print_group_message(idgroup, sender, msg):
    print(f"{BOLD}{ORANGE}[NOTIFICATION]{RESET} {CYAN}GROUP [{idgroup}] - From [{sender}]: {msg}{RESET}")
