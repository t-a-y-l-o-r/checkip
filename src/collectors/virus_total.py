from typing import (
    Optional,
)
from enum import Enum, unique
import multidict
import aiohttp

from .collectors import (
    Collector,
    Collector_Parser,
    Collector_Caller
)


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
    def __init__(self, *args, **kwargs) -> None:
        self._header = "Virus Total"


    def parse(self, raw_report: dict) -> dict:
        assert raw_report is not None
        ip_report = self._parse_ip(raw_report["ip"])
        site_report = self._get_sites_from_resolutions(raw_report["resolutions"])

        additional_info = ip_report["additional_information"]
        additional_info["sites"] = site_report

        return ip_report


    def _parse_ip(self, ip_message: dict) -> dict:
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
        assert ip_message

        attributes_json = ip_message["data"]["attributes"]
        last_results_json = attributes_json["last_analysis_results"]

        owner = attributes_json.get("as_owner", None)
        status = attributes_json.get("last_analysis_stats", dict())
        checked = self._determine_overall_status(status)
        additional_info = self._filter_last_results(last_results_json)

        report = {
            "checked": checked,
            "owner": owner,
            "status": status,
        }

        return {
            "header": self._header,
            "report": report,
            "additional_information": additional_info
        }


    def _determine_overall_status(self, stats: dict) -> str:
        assert stats

        no_scans = all(val == 0 for val in stats.values())
        if no_scans:
            return self._default_status()
        else:
            return self._most_frequent_status(stats)


    def _default_status(self) -> str:
        default_status = VT_Status_Types.harmless.value
        default_symbol = VT_Status_Symbols[default_status]
        return f"{default_status} {default_symbol}"


    def _most_frequent_status(self, stats: dict) -> str:
        status = max(stats, key=lambda key: stats[key])

        valid_status_types = set(status.value for status in VT_Status_Types)
        assert status in valid_status_types

        symbol = VT_Status_Symbols[status]
        return f"{status} {symbol}"


    def _filter_last_results(
            self,
            last_results_json: dict,
            clean: str="clean",
            unrated: str="unrated") -> dict:

        assert last_results_json

        dirty = lambda result: result != "clean" and result != "unrated"
        only_dirty_results = lambda items: dirty(items[1]["result"])
        report = dict(filter(only_dirty_results, last_results_json.items()))

        return report


    def _get_sites_from_resolutions(self, resolutions: dict) -> list:
        if not resolutions:
            return []
        else:
            return [site["attributes"]["host_name"] for site in resolutions["data"]]


'''
            ================
               Caller
            ================
'''


class VT_Caller(Collector_Caller):
    def __init__(self, key: str):
        super().__init__(key)

        if not self.key:
            self.key = ""
        self._header = {"x-apikey": self.key}
        self._session_headers = multidict.CIMultiDict(self._header)
        self._root_endpoint = "https://www.virustotal.com/"
        self._ip_endpoint = "api/v3/ip_addresses/"


    async def call(self, ip: str) -> dict:
        response = {
            call_type.value: await self._call(ip, call_type) for call_type in VT_Call_Type
        }
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
        self._header: Optional[str] = None


    async def header(self) -> None:
        return None


