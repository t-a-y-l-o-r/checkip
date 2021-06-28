from typing import Type, Optional, Dict, List, Any
from abc import ABC, abstractmethod
from enum import Enum, unique
import requests
import config
import json
import os

# async stuff
import aiohttp
import asyncio

'''
Author: Taylor Cochran
'''

#            ================================
#                   Table of Contents
#            ================================
# 1. Globals
# 2. Types
# 3. Factory Stuff
# 4. Collector
# 5. Virus Total
# 6. OTX
# 7. Robtext
#
#

'''
            ================
             Globals
            ================
'''

# VIRUS_TOTAL_KEY = os.environ["VT_KEY"]
# OTX_KEY = os.environ["OTX_KEY"]
'''
CONF = config.Config()
VIRUS_TOTAL_KEY = CONF.virus_total_key
OTX_KEY = CONF.otx_key
'''

'''
            ================
                Types
            ================
'''

@unique
class Collector_Types(Enum):
    VIRUS_TOTAL = 1
    OTX = 2
    ROBTEX = 3

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
        if typeOf == Collector_Types.VIRUS_TOTAL:
            return Virus_Total_Collector(ip=ip)
        elif typeOf == Collector_Types.OTX:
            return OTX_Collector(ip=ip)
        elif typeOf == Collector_Types.ROBTEX:
            return Robtex_Collector(ip=ip)
        else:
            raise TypeError(f"Unknown collector type of {type(typeOf)}")

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
    def __init__(self, ip: Optional[str]=None) -> None:
        self.ip = ip

    @abstractmethod
    def header(self) -> Optional[str]:
        pass

    @abstractmethod
    def report(self) -> Optional[str]:
        pass

'''
=================
Robtext Collector
=================
'''


class Robtex_Collector(Collector):
    '''
    A collector for the Robtext api.
    The api documentation can be found here:
    https://freeapi.robtex.com/api/
    Primarily used to cooberate related ip's and
    geo location data.
    '''
    def __init__(self, ip: str=None) -> None:
        super(Robtex_Collector, self).__init__(ip)
        self._session = requests.Session()
        self._header: Optional[str] = None
        self._report: Optional[str] = None
        self._endpoint: str = "https://freeapi.robtex.com/"

    def header(self) -> Optional[str]:
        if self._header is None:
            self._call_and_parse_all()
        return self._header

    def report(self) -> Optional[str]:
        if self._report is None:
            self._call_and_parse_all()
        return self._report

    def _call_and_parse_all(self) -> None:
        call_dict = self._call().json()
        self._header = "".join([
            "\n\n\t[Robtex]\n\n[asname]: ",
            str(call_dict.get("asname")),
            "\n[whois]: ",
            str(call_dict.get("whoisdesc")),
            "\n[bgproute]: ",
            str(call_dict.get("bgproute")),
            "\n[route]: ",
            str(call_dict.get("routedesc")),
            "\n[country]: ",
            str(call_dict.get("country")),
            "\n[city]: ",
            str(call_dict.get("city")),
            "\n"
        ])
        self._report = json.dumps({
            "passiveDNS" : call_dict.get("pas"),
            "activeDNS": call_dict.get("act")
        }, indent=4, sort_keys=True)

    async def _call(self, call_type: str="ip") -> requests.Response:
        '''
        Calls out to the robtext end point
        https://freeapi.robtex.com/ipquery/{ip}

        Providing and attempting to route the response
        '''
        if call_type is None:
            raise ValueError(f"Invalid call type {call_type}")
        if call_type == "ip":
            endpoint = "{0}/ipquery/{1}".format(endpoint, self.ip)
        response = self._session.get(endpoint)
        code = response.status_code
        if code == 200:
                return response
        elif code == 204:
            raise ValueError("OTX rate limit reached!")
        else:
            raise ValueError(
                "Server reply: {0} Message: {1}".
                format(code, response.text))

async def main(url="https://python.org"):
    '''
    A basic test for the async stuff
    '''
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as request:
            print(f"Status: {request.status}")
            print(f"Type: {request.headers['content-type']}")
            snip = await request.text()
            snip = snip[:100]
            print(f"Body: {snip}")

if __name__ == "__main__":
    ip = "8.8.8.8"
    rob_tex_url = "".join([
        "https://freeapi.robtex.com/",
        "ipquery/",
        ip
    ])
    event_loop = asyncio.get_event_loop()
    event_loop.run_until_complete(main(rob_tex_url))

