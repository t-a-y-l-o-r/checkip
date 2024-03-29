from typing import (
    Optional,
    Any,
    Coroutine,
    Union
)
from abc import ABC, abstractmethod
from enum import Enum, unique


'''
            ================
                Collector
            ================
'''

class Collector_Parser(ABC):
    @abstractmethod
    def parse(self, report: dict) -> dict:
        '''
        Converts the given json report into a string
        '''
        pass


@unique
class Collector_Status(Enum):
    OK = "ok"
    ERROR = "error"


class Collector_Caller(ABC):
    def __init__(self, key: Optional[str]):
        self.key = key # pragma: no cover

    @abstractmethod
    async def call(self, ip: str) -> dict:
        '''
        Converts the given json report into a string
        '''
        pass


class Collector_Core(ABC):
    def __init__(self):
        self._report: Optional[dict] = None # pragma: no cover

    @abstractmethod
    async def report(self) -> Union[Coroutine[Any, Any, Any], dict]:
        pass


class Collector(Collector_Core):
    '''
    Defines the "interface" for the collector module
    All classes should override these methods
    '''
    def __init__(self, *args: Any, **kwargs: Any):
        if len(args) < 1:
            raise ValueError(
                f"Collector expected at least one positional arguments, and instead got: {len(args)}"
            )
        self.ip = ""
        key = args[0]

        caller = kwargs.get("caller")
        if caller:
            self._caller = caller(key)

        parser = kwargs.get("parser")
        if parser:
            self._parser = parser()

        self._report: Optional[dict] = None



    async def report(self) -> Union[Coroutine[Any, Any, Any], dict]:
        if self._report is None:
            result = await self._caller.call(self.ip)
            self._report = self._parser.parse(result)
        return self._report

