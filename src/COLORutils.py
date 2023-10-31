RESET = '\033[0m'

BLACK = '\033[30m'
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
BLUE = '\033[34m'
MAGENTA = '\033[35m'
CYAN = '\033[36m'
WHITE = '\033[37m'

BRIGHT_BLACK = '\033[90m'
BRIGHT_RED = '\033[91m'
BRIGHT_GREEN = '\033[92m'
BRIGHT_YELLOW = '\033[93m'
BRIGHT_BLUE = '\033[94m'
BRIGHT_MAGENTA = '\033[95m'
BRIGHT_CYAN = '\033[96m'
BRIGHT_WHITE = '\033[97m'

def style_text(color_code, text):
    return f"{color_code}{text}{RESET}"

def black(text):
    return style_text(BLACK, text)

def red(text):
    return style_text(RED, text)

def green(text):
    return style_text(GREEN, text)

def yellow(text):
    return style_text(YELLOW, text)

def blue(text):
    return style_text(BLUE, text)

def magenta(text):
    return style_text(MAGENTA, text)

def cyan(text):
    return style_text(CYAN, text)

def white(text):
    return style_text(WHITE, text)

def bright_black(text):
    return style_text(BRIGHT_BLACK, text)

def bright_red(text):
    return style_text(BRIGHT_RED, text)

def bright_green(text):
    return style_text(BRIGHT_GREEN, text)

def bright_yellow(text):
    return style_text(BRIGHT_YELLOW, text)

def bright_blue(text):
    return style_text(BRIGHT_BLUE, text)

def bright_magenta(text):
    return style_text(BRIGHT_MAGENTA, text)

def bright_cyan(text):
    return style_text(BRIGHT_CYAN, text)

def bright_white(text):
    return style_text(BRIGHT_WHITE, text)