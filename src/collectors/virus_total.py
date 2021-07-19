from typing import (
    Optional,
    Dict,
    List,
    Any,
    Coroutine,
    Union
)
from enum import Enum, unique
import aiohttp

from .collectors import (
    Collector,
    Collector_Parser,
    Collector_Caller
)

import json

'''
            ================
               Globals
            ================
'''

@unique
class VT_Call_Type(Enum):
    ip = "ip"
    resolutions = "resolutions"


@unique
class VT_Status_Types(Enum):
    harmless = "harmless"
    malicious = "malicious"
    suspicious = "suspicious"
    undetected = "undetected"
    timeout = "timeout"


VT_Status_Symbols = {
    VT_Status_Types.harmless.value: "✅",
    VT_Status_Types.malicious.value: "❌",
    VT_Status_Types.suspicious.value: "❌",
    VT_Status_Types.undetected.value: "❓",
    VT_Status_Types.timeout.value: "❓",
}

'''
            ================
               Parser
            ================
'''

class VT_Parser(Collector_Parser):
    def parse(self, raw_report: dict) -> dict:
        assert raw_report is not None
        ip_report = self._parse_ip(raw_report["ip"])
        site_report = self._parse_resolutions(raw_report["resolutions"])

        additional_info = ip_report["additional_information"]
        additional_info["sites"] = site_report

        return ip_report

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
        assert json_message
        header = "Virus Total"

        data = json_message["data"]
        attributes = data["attributes"]
        owner = attributes["as_owner"]

        analysis_json = attributes["last_analysis_stats"]
        stats = self._last_stats(analysis_json)
        checked = self._determine_overall_status(stats)

        analysis_json = attributes["last_analysis_results"]
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


    def _last_stats(self, analysis_json: dict) -> dict:
        stats = {status.value: 0 for status in VT_Status_Types}

        for scan in analysis_json.keys():
            scan_result = analysis_json[scan]
            stats[scan] += scan_result

        return stats


    def _determine_overall_status(self, stats: dict) -> str:
        has_most = VT_Status_Types.harmless.value
        most = 0

        for stat_type in stats.keys():
            count = stats[stat_type]
            if count > most:
                most = count
                has_most = stat_type

        symbol = VT_Status_Symbols[has_most]
        overall_status = f"{has_most} {symbol}"
        return overall_status


    def _last_results(
            self,
            analysis_json: dict,
            clean: str="clean",
            unrated: str="unrated") -> dict:

        assert analysis_json is not None

        report = {}
        for stat in analysis_json.keys():
            agency = analysis_json[stat]
            result = agency["result"]
            if result != clean and result != unrated:
                report[stat] = agency

        return report


    def _parse_resolutions(self, response: dict) -> List[str]:
        if not response:
            return []
        sites = []
        data = response["data"]
        for site_data in data:
            attributes = site_data["attributes"]
            host = attributes["host_name"]
            sites.append(host)
        return sites


'''
            ================
               Caller
            ================
'''


class VT_Caller(Collector_Caller):
    def __init__(self, *args):
        super().__init__(args[0])

        self._session_headers = {'x-apikey': self.key}
        self._root_endpoint: str = 'https://www.virustotal.com/'
        self._ip_endpoint: str = 'api/v3/ip_addresses/'


    async def call(self, ip) -> dict:
        response = dict()
        for call_type in VT_Call_Type:
            response[call_type.value] = await self._call(ip, call_type)
        return response


    async def _call(self, ip: str, call_type: VT_Call_Type, limit: int=20) -> dict:
        endpoint = self._generate_endpoint(ip, call_type, limit)
        return await self._get(endpoint)


    def _generate_endpoint(self, ip: str, call_type: VT_Call_Type, limit) -> str:

        assert call_type in VT_Call_Type

        url_call_type = f"/{call_type.value}"
        limit_str = f"?limit={limit}"

        if call_type is VT_Call_Type.ip:
            url_call_type = ""
            limit_str = ""

        return "".join([
            self._root_endpoint,
            self._ip_endpoint,
            ip,
            url_call_type,
            limit_str,
        ])


    async def _get(self, endpoint: str) -> dict:
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


'''
            ================
               Collector
            ================
'''


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
        super().__init__(ip, key, caller=VT_Caller, parser=VT_Parser)
        self._header: Any = None

    async def header(self) -> None:
        return None

