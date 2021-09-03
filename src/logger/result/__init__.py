@unique
class Result(Enum):
    OK="ok"
    ERR="error"

def wrap(func: callable) -> callable:

    @wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        try:
            return (Result.OK, func(*args, **kwargs))
        except Exception as e:
            return (Result.ERR, e)
    return wrapper

def async_wrap(func: callable):
    @wraps(func)
    async def wrapper(*args, **kwargs) -> Any:
        try:
            res = await func(*args, **kwargs)
            return (Result.OK, res)
        except Exception as e:
            return (Result.ERR, e)
    return wrapper

