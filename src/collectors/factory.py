from abc import ABC, abstractmethod
from enum import Enum, unique

import config

from .collectors import Collector

from .virus_total import Virus_Total_Collector # noqa: F401
from .otx import OTX_Collector # noqa: F401
from .robtex import Robtex_Collector # noqa: F401



'''
            ================
                Types
            ================
'''

@unique
class Collector_Types(Enum):
    VIRUS_TOTAL = "Virus_Total_Collector"
    OTX = "OTX_Collector"
    ROBTEX = "Robtex_Collector"


'''
            ================
                Config
            ================
'''
CONF = config.Config()
VIRUS_TOTAL_KEY = CONF.virus_total_key
OTX_KEY = CONF.otx_key

KEYS = {
    Collector_Types.VIRUS_TOTAL.value: VIRUS_TOTAL_KEY,
    Collector_Types.OTX.value: OTX_KEY,
}


'''
            ================
               Factories
            ================
'''

class Abstract_Collector_Factory(ABC):
    '''
    Abstract factory for the collectors defined in this module
    '''
    @abstractmethod
    def of(self, type: Collector_Types, ip: str=None) -> "Collector":
        pass

class Collector_Factory(Abstract_Collector_Factory):
    '''
    Concrete factory for the collectors defined within this module
    '''
    def of(self, typeOf: Collector_Types, ip: str=None) -> "Collector":
        assert typeOf in Collector_Types
        name = typeOf.value
        key = None if name not in KEYS else KEYS[name]
        return globals()[typeOf.value](ip, key)
