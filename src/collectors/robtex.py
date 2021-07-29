from typing import (
    Optional,
    Any,
    Tuple,
    Coroutine,
    Union
)
import requests
import json

# async stuff
import aiohttp

from .collectors import (
    Collector,
    Collector_Parser,
    Collector_Caller
)

'''
        =================
        Robtext Collector
        =================
'''

class Robtex_Parser(Collector_Parser):
    def __init__(self, *args, **kwargs) -> None:
        self._header = "Robtex"


    def parse(self, raw_report: dict) -> dict:
        output = {"header": self._header}
        error_message = raw_report.get("ERROR", None)

        if raw_report.get("ERROR", None):
            output["report"] = error_message
        else:
            output["report"] = self._build_report(raw_report)
            output["additional_information"] = self._build_additional_information(raw_report)
        return output


    def _build_report(self, call_dict: dict) -> dict:
        assert call_dict is not None
        report = {
                "asname": call_dict.get("asname", None),
                "whois": call_dict.get("whoisdesc", None),
                "bgproute": call_dict.get("bgproute", None),
                "routedesc": call_dict.get("routedesc", None),
                "country": call_dict.get("country", None),
                "country": call_dict.get("city", None),
        }
        return report


    def _build_additional_information(self, call_dict: dict) -> dict:
        assert call_dict is not None
        additional_information =  {
            "passiveDNS" : call_dict.get("pas", None),
            "activeDNS": call_dict.get("act", None)
        }
        return additional_information


class Robtex_Caller(Collector_Caller):
    def __init__(self, key: str) -> None:
        super().__init__(key)
        self._endpoint: str = "https://freeapi.robtex.com"

    async def call(self, ip: str) -> dict:
        return await self._call(ip, call_type="ip")

    async def _call(self, ip: str, call_type: str="ip") -> dict:
        '''
        Calls out to the robtext end point
        https://freeapi.robtex.com/ipquery/{ip}

        Providing and attempting to route the response
        '''
        if call_type is None:
            raise ValueError(f"Invalid call type {call_type}")
        endpoint = ""
        if call_type == "ip":
            endpoint = "".join([
                self._endpoint,
                "/ipquery/",
                ip
            ])

        async with aiohttp.ClientSession() as session:
            async with session.get(endpoint) as response:
                code = response.status
                if code == 200:
                    return await response.json()
                elif code == 429:
                    return {"ERROR": "rate limit reached"}
                else:
                    text = await response.json()
                    raise IOError(f"Server reply: {code} Message: {text}")



class Robtex_Collector(Collector):
    '''
    A collector for the Robtext api.
    The api documentation can be found here:
    https://freeapi.robtex.com/api/
    Primarily used to cooberate related ip's and
    geo location data.
    '''
    def __init__(self, ip: str=None, key: str=None) -> None:
        super().__init__(ip, key, caller=Robtex_Caller, parser=Robtex_Parser)
        self._header: Optional[str] = None

    async def header(self) -> None:
        return None


    ## TODO: Delete these
    async def old_header(self) -> Union[Coroutine[Any, Any, Any], str]:
        if self._header is None:
            await self._call_and_parse_all()
        assert self._header is not None
        return self._header

    async def old_report(self) -> Union[Coroutine[Any, Any, Any], str]:
        if self._report is None:
            await self._call_and_parse_all()

        assert self._report is not None
        report = dict()

        report["header"] = self._header
        report["report"] = self._report

        return report
