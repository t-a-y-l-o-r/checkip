from typing import Any, Callable
from functools import wraps
import traceback
import logging

import inspect


RED = "\033[91m"
YELLOW = "\033[93m"
CLEAR = "\033[0m"


logging.basicConfig(
    filename=".log",
    filemode="w",
    format="%(name)s - %(levelname)s - %(message)s",
    level=logging.DEBUG
)
_LOGGER = logging.getLogger("checkip")

def _error_message(error_type: str, func: Callable, exc: Exception) -> str:
    return "".join([
        f"[*] {RED} Warning:{CLEAR} ",
        f"{YELLOW} ({error_type}, {func.__name__}) -- ",
        f"{exc.__class__.__name__} {CLEAR} {exc}\n\r",
        f"{inspect.getmodule(func)}"
    ])

def _user_message(error_type: str, func_name: str, exc: Exception) -> str:
    return "".join([
        f"[*] {RED} Warning:{CLEAR} ",
        f"{YELLOW} ({error_type}, {func_name}) -- ",
        f"{exc.__class__.__name__} {CLEAR} {exc}",
        "\n\rPlease Contact Developer"
    ])


def internal(func: Callable) -> Callable:
    @wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        try:
            return func(*args, **kwargs)
        except Exception as e:
            error_message = _error_message("Internal Error", func, e)
            _LOGGER.error(traceback.format_exc())
            _LOGGER.error(error_message)
    return wrapper

