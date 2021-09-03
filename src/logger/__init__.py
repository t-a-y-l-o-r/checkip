from typing import Any, Callable, Tuple
from functools import wraps
import traceback
import logging


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

def error_message(error_type: str, func_name: str, exc: Exception) -> str:
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
            _LOGGER.error(traceback.format_exc())
            raise Exception(error_message("Internal Error", func.__name__, e))
    return wrapper


def network(call_types: Tuple[str]) -> Callable:
    assert _valid_call_types(call_types)

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            try:
                response = await func(*args, **kwargs)

                code, result = response
                _raise_if_outside_types(code, call_types)

                return result
            except OSError as e:
                message = error_message(f"Networking Error", func.__name__, e)
                if not e.args:
                    e.args = ('', )

                e.args = (message,)
                _LOGGER.error(e)
                raise

        return wrapper
    return decorator

def _raise_if_outside_types(code: int, call_types: Tuple[str]) -> None:
    within_types = lambda code, call_types: str(code) in call_types

    if not within_types(code, call_types):
        raise OSError("".join([
            "Unexpected https code outside list of acceptable codes. ",
            f"Found {code}, expected one of {call_types}"
        ]))


def _valid_call_types(call_types: Tuple[str]) -> bool:
    valid = call_types is not None

    within_bounds = lambda val: 100 <= val and val <= 599
    valid = valid and all([within_bounds(int(val)) for val in call_types])

    return valid

