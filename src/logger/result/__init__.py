from enum import Enum, unique
from typing import Any, Callable
from functools import wraps

@unique
class Result(Enum):
    OK = "ok"
    ERR = "error"

def wrap(func: Callable) -> Callable:

    @wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        try:
            return (Result.OK, func(*args, **kwargs))
        except Exception as e:
            return (Result.ERR, e)
    return wrapper

def async_wrap(func: Callable):
    @wraps(func)
    async def wrapper(*args, **kwargs) -> Any:
        try:
            res = await func(*args, **kwargs)
            return (Result.OK, res)
        except Exception as e:
            return (Result.ERR, str(e))
    return wrapper

