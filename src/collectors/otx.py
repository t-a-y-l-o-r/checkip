from typing import (
    Optional,
    Dict,
    List,
    Any,
    Coroutine,
    Union
)
from enum import Enum, unique

# async stuff
import aiohttp

from .collectors import (
    Collector,
    Collector_Parser,
    Collector_Caller
)


class OTX_Parser(Collector_Parser):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._header = "OTX"

    def parse(self, raw_report: dict) -> dict:

        general_raw = raw_report[OTX_Call_Type.GENERAL.value]
        report = self._build_report(general_raw)

        reputation_raw = raw_report[OTX_Call_Type.REPUTATION.value]
        url_list_raw = raw_report[OTX_Call_Type.URL_LIST.value]

        additional_information = self._build_add_info(reputation_raw, url_list_raw)

        clean_report = {
            "header": self._header,
            "report": report,
            "additional_information": additional_information
        }

        return clean_report


    def _build_add_info(self, reputation_raw: dict, url_list_raw: dict) -> dict:
        reputation = self._parse_reputation(reputation_raw)
        url_list = self._parse_url_list(url_list_raw)

        return {
            "reputation": reputation,
            "domains": url_list
        }


    def _build_report(self, response: dict) -> Dict[str, Any]:
        return {
            "asn": response.get("asn", None),
            "Country": response.get("country_name", None),
            "City": response.get("city", None),
            "Threat Score": response.get("thread_score", None),
            "Type": response.get("type_of_activities", None)
        }


    def _parse_reputation(self, response: dict) -> dict:
        if not response:
            return None

        counts = response.get("counts", None)
        return {
            "threat_score": response.get("threat_score", None),
            "type_of_activities": list(counts.keys()) if counts else None,
            "last_seen": response.get("last_seen", None),
            "domains": response.get("domains", None)
        }


    def _parse_url_list(self, response: dict) -> List[str]:
        json = response
        urls = json.get("url_list")
        assert urls is not None
        url_list = []
        domain = ""
        for url in urls:
            domain = url.get("domain")
            if domain != "" and domain is not None:
                url_list.append(domain)
        return url_list

@unique
class OTX_Call_Type(Enum):
    GENERAL = "general"
    REPUTATION = "reputation"
    URL_LIST = "url_list"

class OTX_Caller(Collector_Caller):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._session_headers: dict = {'X-OTX-API-KEY': self.key}
        self._general: Optional[Dict[Any, Any]] = None
        self._reputation: Optional[Dict[Any, Any]] = None
        self._url_list: Optional[List[str]] = None
        self._endpoint = "https://otx.alienvault.com/api/v1/indicators/IPv4/"


    async def call(self, ip: str) -> dict:
        # call everything and parse individually

        caller = lambda call_type: self._call(ip, call_type=call_type)
        call_data = {call_type.value: await caller(call_type) for call_type in OTX_Call_Type}

        return call_data


    async def _call(self, ip: str, call_type: OTX_Call_Type=None) -> dict:
        '''
        Call out to a given enpoint based on the call_type.
        provides a response if possible
        '''
        if call_type is None:
            raise ValueError("Invalid call type {call_type}")

        call_type = call_type.value

        endpoint = f"{self._endpoint}/{ip}/{call_type}"
        async with aiohttp.ClientSession(headers=self._session_headers) as session:
            async with session.get(endpoint) as response:
                code = response.status
                if code == 200:
                    return await response.json()
                elif code == 204:
                    raise ValueError("OTX rate limit reached!")
                else:
                    text = await response.text()
                    raise ValueError(f"Server reply: {code} Message: {text}")



class OTX_Collector(Collector):
    '''
    Defines the collector for the OTX api.
    Relevent endpoints:
    https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/{section}
    Where ip is the ip and section is the kind
    of data to query for. i.e. "general", "reputation", or "url_list"
    '''
    def __init__(self, ip: str=None, key: str=None) -> None:
        super().__init__(ip, key, caller=OTX_Caller, parser=OTX_Parser)

    async def header(self) -> None:
        return None


