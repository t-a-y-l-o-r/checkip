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

from .collectors import Collector

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
    def __init__(self, ip: str=None, key=None) -> None:
        super().__init__(ip, key)
        self._session = requests.Session()
        self._header: Optional[str] = None
        self._report: Optional[str] = None
        self._endpoint: str = "https://freeapi.robtex.com"

    async def header(self) -> Union[Coroutine[Any, Any, Any], str]:
        if self._header is None:
            await self._call_and_parse_all()
        assert self._header is not None
        return self._header

    async def report(self) -> Union[Coroutine[Any, Any, Any], str]:
        if self._report is None:
            await self._call_and_parse_all()
        assert self._report is not None
        return self._report

    async def _call_and_parse_all(self) -> None:
        call_dict = None
        try:
            call_dict = await self._call()
        except ValueError as e:
            call_dict = None

        if call_dict is None:
            self._header, self._report = self._build_rate_limit_header()
        else:
            self._header, self._report = self._build_safe_report(call_dict)

    def _build_rate_limit_header(self) -> Tuple[Any, Any]:
        header = "".join([
            "\n\n\t[Robtex]\n\n",
            "[ERROR]: Rate limit reached\n\n",
        ])
        report = {"ERROR": "rate limit reached"}
        return (header, report)

    def _build_safe_report(self, call_dict: dict) -> Tuple[Any, Any]:
        assert call_dict is not None
        header = "".join([
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
        report = json.dumps(
            {
                "passiveDNS" : call_dict.get("pas"),
                "activeDNS": call_dict.get("act")
            },
            indent=4,
            sort_keys=True
        )
        return header, report

    async def _call(self, call_type: str="ip") -> dict:
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
                str(self.ip)
            ])

        async with aiohttp.ClientSession() as session:
            async with session.get(endpoint) as response:
                code = response.status
                if code == 200:
                        return await response.json()
                elif code == 429:
                    raise ValueError("Robtex rate limit reached!")
                else:
                    text = await response.json()
                    raise IOError(f"Server reply: {code} Message: {text}")
