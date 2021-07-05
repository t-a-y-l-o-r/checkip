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

class Collector(ABC):
    '''
    Defines the "interface" for the collector module
    All classes should override these methods
    '''
    def __init__(self, ip: Optional[str]=None, key: Optional[str]=None) -> None:
        self.ip = ip
        self.key = key

    @abstractmethod
    def report(self) -> Union[Coroutine[Any, Any, Any], dict]:
        pass
