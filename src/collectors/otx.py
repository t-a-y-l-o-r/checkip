from typing import (
    Dict,
    List,
    Any,
)
from enum import Enum, unique

# async stuff
import aiohttp

from .collectors import (
    Collector,
    Collector_Parser,
    Collector_Caller,
)


@unique
class OTX_Call_Type(Enum):
    GENERAL = "general"
    REPUTATION = "reputation"
    URL_LIST = "url_list"


class OTX_Parser(Collector_Parser):
    def __init__(self, *args, **kwargs) -> None:
        self._header = "OTX"


    def parse(self, raw_report: dict) -> dict:
        raise ValueError("hello")
        if not raw_report:
            return self._empty_report()

        general_raw = raw_report.get(OTX_Call_Type.GENERAL.value, None)
        report = self._build_report(general_raw)

        reputation_raw = raw_report.get(OTX_Call_Type.REPUTATION.value, None)
        url_list_raw = raw_report.get(OTX_Call_Type.URL_LIST.value, None)

        additional_information = self._build_add_info(reputation_raw, url_list_raw)

        clean_report = {
            "header": self._header,
            "report": report,
            "additional_information": additional_information
        }

        return clean_report

    def _empty_report(self) -> dict:
        return {
            "header": None,
            "report": None,
            "additional_information": None
        }


    def _build_report(self, response: dict) -> Dict[str, Any]:
        if not response:
            return dict()

        return {
            "asn": response.get("asn", None),
            "Country": response.get("country_name", None),
            "City": response.get("city", None),
            "Threat Score": response.get("thread_score", None),
            "Type": response.get("type_of_activities", None)
        }


    def _build_add_info(self, reputation_raw: dict, url_list_raw: dict) -> dict:
        reputation = self._parse_reputation(reputation_raw)
        url_list = self._parse_url_list(url_list_raw)

        return {
            "reputation": reputation,
            "url_list": url_list
        }


    def _parse_reputation(self, response: dict) -> dict:
        if not response:
            return dict()

        reputation = response.get("reputation", None)
        reputation = dict() if not reputation else reputation

        counts = reputation.get("counts", None)
        return {
            "threat_score": reputation.get("threat_score", None),
            "type_of_activities": list(counts.keys()) if counts else None,
            "last_seen": reputation.get("last_seen", None),
            "domains": reputation.get("domains", None)
        }


    def _parse_url_list(self, response: dict) -> List[str]:
        if not response:
            return []

        raw_url_list = response.get("url_list", [])
        flattened_url_list = [url["domain"] for url in raw_url_list]

        valid_domain = lambda domain: domain != "" and domain is not None
        url_list = list(filter(valid_domain, flattened_url_list))

        return url_list



class OTX_Caller(Collector_Caller):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._session_headers: dict = {'X-OTX-API-KEY': self.key}
        self._endpoint = "https://otx.alienvault.com/api/v1/indicators/IPv4/"


    async def call(self, ip: str) -> dict:
        caller = lambda call_type: self._call(ip, call_type)
        call_data = {call_type.value: await caller(call_type) for call_type in OTX_Call_Type}

        return call_data


    async def _call(self, ip: str, call_type: OTX_Call_Type) -> dict:
        '''
        Call out to a given enpoint based on the call_type.
        provides a response if possible
        '''
        assert call_type in OTX_Call_Type
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
                    type_is = response.content_type
                    text = await self._handle_response_type(response)
                    raise IOError(text)

    async def _handle_response_type(self, response: aiohttp.ClientResponse) -> dict:
        type_is = response.content_type
        if type_is == "text/html":
            return {"Message": await response.text()}
        else:
            return {"Message": await response.json()}


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


