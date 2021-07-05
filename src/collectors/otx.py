from typing import (
    Optional,
    Dict,
    List,
    Any,
    Coroutine,
    Union
)
import json

# async stuff
import aiohttp

from .collectors import Collector

'''
            ================
                  OTX
            ================
'''

class OTX_Collector(Collector):
    '''
    Defines the collector for the OTX api.
    Relevent endpoints:
    https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/{section}
    Where ip is the ip and section is the kind
    of data to query for. i.e. "general", "reputation", or "url_list"
    '''
    def __init__(self, ip: str=None, key=None) -> None:
        super().__init__(ip, key)
        self.key = key
        self._session_headers: dict = {'X-OTX-API-KEY': self.key}
        self._header: Optional[str] = None
        self._report: Optional[str] = None
        self._general: Optional[Dict[Any, Any]] = None
        self._reputation: Optional[Dict[Any, Any]] = None
        self._url_list: Optional[List[str]] = None
        self._endpoint = "https://otx.alienvault.com/api/v1/indicators/IPv4/"

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
        # call everything and parse individually
        general = await self._call(call_type="general")
        self._general = self._parse_general(general)
        reputation = await self._call(call_type="reputation")
        self._reputation = self._parse_reputation(reputation)

        url_list = await self._call(call_type="url_list")
        self._url_list = self._parse_urls(url_list)
        # convert into human readable
        if self._general is None:
            raise ValueError(
                f"request response body cannot be None type!"
            )
        self._header = "".join([
            "\n\t[OTX]\n\n",
            "[asn]: ",
            str(self._general.get("asn")),
            "\n[Country]: ",
            str(self._general.get("country_name")),
            "\n[City]: ",
            str(self._general.get("city")),
            "\n[Threat Level]: ",
            str(self._general.get("threat_score")),
            "\n[Type]: ",
            str(self._general.get("type_of_activities")),
        ])
        report = {
            "last_seen": self._reputation.get("last_seen"),
            "type_of_activities": self._reputation.get("type_of_activities"),
            "domains": self._url_list
        }
        self._report = json.dumps(
            report,
            indent=4,
            sort_keys=True
        )

    async def _call(self, call_type: str=None) -> dict:
        '''
        Call out to a given enpoint based on the call_type.
        provides a response if possible
        '''
        if call_type is None:
            raise ValueError("Invalid call type {call_type}")

        endpoint = f"{self._endpoint}/{self.ip}/{call_type}"
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

    def _parse_general(self, response: dict) -> Dict[str, Any]:
        json = response
        asn = json.get("asn")
        assert asn is not None
        country_name = json.get("country_name")
        city = json.get("city")
        return {
            "asn": asn,
            "country_name": country_name,
            "city": city,
        }

    def _parse_reputation(self, response: dict) -> dict:
        json = response
        reputation = json.get("reputation")
        threat_score = None
        type_of_activities = None
        last_seen = None
        domains = None
        if reputation is not None:
            threat_score = reputation.get("threat_score")
            type_of_activities = list(reputation.get("counts").keys())
            last_seen = reputation.get("last_seen")
            domains = reputation.get("domains")
        return {
            "threat_score": threat_score,
            "type_of_activities": type_of_activities,
            "last_seen": last_seen,
            "domains": domains
        }

    def _parse_urls(self, response: dict) -> List[str]:
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
