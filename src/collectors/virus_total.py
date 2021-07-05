from typing import (
    Type,
    Optional,
    Dict,
    List,
    Any,
    Tuple,
    Coroutine,
    Union
)
from abc import ABC, abstractmethod
from enum import Enum, unique
import json

# async stuff
import aiohttp
import asyncio

from .collectors import Collector
'''
            ================
              Virus Total
            ================
'''

class VT_Status_Types(Enum):
    harmless = "harmless"
    malicious = "malicious"
    suspicious = "suspicious"
    undetected = "undetected"
    timeout = "timeout"

class Virus_Total_Collector(Collector):
    '''
    Defines the collector for the virustotal api.
    Main endpoints
        https://www.virustotal.com/api/v3/
        https://www.virustotal.com/api/v3/ip_addresses/{ip}/{relationship}
    Where ip is the ip and relationship is the additioanl
    data being requested
    '''
    def __init__(self, ip=None, key=None) -> None:
        super(Virus_Total_Collector, self).__init__(ip, key)

        self._session_headers: dict = {'x-apikey': self.key}

        self._header: Any = None
        self._report: Optional[str] = None

        self._root_endpoint: str = 'https://www.virustotal.com/'
        self._ip_endpoint: str = 'api/v3/ip_addresses/'

        self._analysis_types = VT_Status_Types
        self._analysis_symbols = {
            self._analysis_types.harmless.value: "✅",
            self._analysis_types.malicious.value: "❌",
            self._analysis_types.suspicious.value: "❌",
            self._analysis_types.undetected.value: "❓",
            self._analysis_types.timeout.value: "❓",
        }


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
        response = await self._call("ip")
        parsed_dict = self._parse_ip(response)
        response = await self._call("resolutions")
        sites = self._parse_resolutions(response)

        parsed_dict["additional_information"] = {
            "sites": sites
        }
        self._header = parsed_dict["header"]
        self._report = parsed_dict


    async def _call(self, call_type: str="ip", limit: int=20) -> dict:
        '''
        Call out to a given enpoint based on the call_type.

        If call_type is not set then the default endpoint is selcted.
        Otherwise resolutions is called if selected.
        As a fail safe the un-implemented selections the
        function will throw a ValueError if it can't parse the
        call_type.

        Returns the reponse if it determines it is valid
        '''
        limit_str = str(limit)
        if call_type is None:
            raise ValueError("Call type cannot be none")
        if call_type == "ip":
            call_type = ""
            limit_str = ""
        else:
            call_type = f"/{call_type}"
            limit_str = f"?limit={limit_str}"
        endpoint = "".join([
            self._root_endpoint,
            self._ip_endpoint,
            str(self.ip),
            call_type,
            limit_str,
        ])
        async with aiohttp.ClientSession(headers=self._session_headers) as session:
            async with session.get(endpoint) as response:
                code = response.status
                if code == 200:
                    return await response.json()
                elif code == 204:
                    raise ValueError("Virustotal rate limit reached!")
                else:
                    text = await response.text()
                    raise ValueError(f"Server reply: {code} Message: {text}")


    def _parse_ip(self, json_message: dict) -> dict:
        '''
        Parses the raw response body and converts it into a human
        readable format.

        In the event the ip is found to be worth further investigation
        will call out for realted site information and append to the
        report data.
        ✅
        ❌
        ❓
        '''
        header = "Virus Total"

        data = json_message["data"]
        attributes = data["attributes"]
        owner = attributes["as_owner"]

        analysis_json = attributes.get("last_analysis_stats")
        stats = self._last_stats(analysis_json)
        checked = self._determine_overall_status(stats)

        analysis_json = attributes.get("last_analysis_results")
        additional_info = self._last_results(analysis_json)

        report = {
            "checked": checked,
            "owner": owner,
            "stats": stats,
        }

        return {
            "header": header,
            "report": report,
            "additional_information": additional_info
        }


    def _last_results(
            self,
            analysis_json: dict,
            clean: str="clean",
            unrated: str="unrated") -> dict:

        report = {}
        for stat in analysis_json.keys():
            agency = analysis_json.get(stat)
            assert agency is not None
            result = agency.get("result")
            if result != clean and result != unrated:
                report[stat] = agency

        return report


    def _last_stats(self, analysis_json: dict) -> dict:

        stats: Dict[Any, int] = dict()
        for result in self._analysis_types:
            stats[result.value] = 0

        for scan in analysis_json.keys():
            scan_result = analysis_json.get(scan)
            assert scan_result is not None
            stats[scan] += scan_result

        return stats


    def _determine_overall_status(self, stats: dict) -> str:

        has_most = self._analysis_types.harmless.value
        most = 0

        for stat_type in stats.keys():
            count = stats[stat_type]
            if count > most:
                most = count
                has_most = stat_type

        symbol = self._analysis_symbols[has_most]
        overall_status = f"{has_most} {symbol}"
        return overall_status


    def _parse_resolutions(self, response: dict) -> List[str]:

        sites = []
        relations_response = response
        data = relations_response.get("data")
        assert data is not None
        for site_data in data:
            attributes = site_data.get("attributes")
            host = attributes.get("host_name")
            sites.append(host)
        return sites
