from typing import (
    Optional,
    Any,
    Coroutine,
    Union
)
from abc import ABC, abstractmethod

'''
            ================
                Collector
            ================
'''

class Collector_Parser(ABC):

    @abstractmethod
    def parse(self, report: dict) -> str:
        '''
        Converts the given json report into a string
        '''
        pass


class Collector_Caller(ABC):
    def __init__(self, ip: str, key: Optional[str]):
        self.ip = ip
        self.key = key

    @abstractmethod
    def call(self, ip: str) -> dict:
        '''
        Converts the given json report into a string
        '''
        pass


class Collector_Core(ABC):

    def __init__(self):
        self._report: Optional[dict] = None

    @abstractmethod
    async def report(self) -> Union[Coroutine[Any, Any, Any], dict]:
        pass



class Collector(Collector_Core):
    '''
    Defines the "interface" for the collector module
    All classes should override these methods
    '''
    def __init__(self, *args, **kwargs):
        ip = args[0]
        key = args[1]

        caller = kwargs.get("caller")
        if caller:
            self._caller = caller(ip, key)

        parser = kwargs.get("parser")
        if parser:
            self._parser = parser()


    async def report(self) -> Union[Coroutine[Any, Any, Any], dict]:
        if self._report is None:
            self._report = await self._parser.parse(self._caller.call())
        return self._report
