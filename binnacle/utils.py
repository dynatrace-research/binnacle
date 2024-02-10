import os
import platform
import re
import socket
import struct
import subprocess
import time
from functools import wraps

from loguru import logger

KEBAB_CASE_PATTERN = re.compile(r"(?<!^)(?=[A-Z])")


def to_kebab_case(string: str) -> str:
    return KEBAB_CASE_PATTERN.sub("-", string).replace("_", "-").lower()


def kebap_case_to_pascal_case(text: str) -> str:
    return "".join([f.title() for f in text.split("-")])


def convert_ip_to_int(ip: str) -> int:
    packedIP = socket.inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]


def convert_int_to_ip(ip: int) -> str:
    return socket.inet_ntoa(struct.pack("!L", ip))


def startfile(file: str) -> None:
    match platform.system():
        case "Linux":
            subprocess.run(["xdg-open", file])
        case "Windows":
            os.startfile(file)
        case "Darwin":
            subprocess.call(("open", file))
        case _:
            logger.warning(f"Can't open file on platform {platform.system()}")


def measure(fn):
    @wraps(fn)
    def _wrapper(*args, **kwargs):
        start = time.perf_counter()
        res = fn(*args, **kwargs)
        end = time.perf_counter()
        total = end - start
        logger.debug(f"{fn.__name__} took {total:.2f}s ({len(res)} elements)")
        return res

    return _wrapper
