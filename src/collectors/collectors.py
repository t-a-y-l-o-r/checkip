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
import requests
import config
import json
import os

# async stuff
import aiohttp
import asyncio

import time
import cProfile

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

CONF = config.Config()
VIRUS_TOTAL_KEY = CONF.virus_total_key
OTX_KEY = CONF.otx_key

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
        return globals()[typeOf.value](ip)

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
    def report(self) -> Union[Coroutine[Any, Any, Any], dict]:
        pass

'''
            ================
              Virus Total
            ================
'''

class VT_Status_Types(Enum):
    harmless = "harmless"
    malicious = "malicious"
    suspiscious = "suspiscious"
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
    def __init__(self, ip=None) -> None:
        super(Virus_Total_Collector, self).__init__(ip)

        self._session_headers: dict = {'x-apikey': VIRUS_TOTAL_KEY}

        self._header: Optional[str] = None
        self._report: Optional[str] = None

        self._root_endpoint: str = 'https://www.virustotal.com/'
        self._ip_endpoint: str = 'api/v3/ip_addresses/'

        self._analysis_types = VT_Status_Types
        self._analysis_symbols = {
            self._analysis_types.harmless.value: "✅",
            self._analysis_types.malicious.value: "❌",
            self._analysis_types.suspiscious.value: "❌",
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

        self._header = parsed_dict
        '''
        self._header = "".join([
            parsed_dict["header"],
            "\n",
            parsed_dict["checked"],
            "\n",
            parsed_dict["owner"],
            "\n",
            parsed_dict["stats"]
        ])
        '''
        report = json.loads(parsed_dict["report"])
        report["sites"] = sites
        self._report = json.dumps(report, sort_keys=True, indent=4)

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

    def _parse_ip(self, json_message: dict) -> Dict[str, str]:
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
        report = {}
        data = json_message["data"]
        attributes = data["attributes"]
        owner = attributes["as_owner"]

        owner = f"[Owner] {owner}"

        header = "\t[Virus Total]\n"
        checked = "[Unknown] ✅"

        analysis_json = attributes.get("last_analysis_stats")

        stats = self._build_last_analysis_stats(analysis_json)
        checked = self._determine_overall_status(stats)

        analysis_json = attributes.get("last_analysis_results")
        for key in analysis_json.keys():
            agency = analysis_json.get(key)
            result = agency.get("result")
            if result != "clean" and result != "unrated":
                report[(f"{key}")] = agency
        return {
            "header": header,
            "checked": checked,
            "owner": owner,
            "stats": stats,
            "report": json.dumps(report)
        }

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


    def _build_last_analysis_stats(self, analysis_json: dict) -> dict:

        stats = dict()
        for result in self._analysis_types:
            stats[result.value] = 0

        for scan in analysis_json.keys():
            result = analysis_json.get(scan)
            stats.setdefault(scan, 0)
            stats[scan] += result

        return stats


    def _parse_resolutions(self, response: dict) -> List[str]:
        # get relations data
        sites = []
        relations_response = response
        data = relations_response.get("data")
        assert data is not None
        for site_data in data:
            attributes = site_data.get("attributes")
            host = attributes.get("host_name")
            sites.append(host)
        return sites

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
    def __init__(self, ip: str=None) -> None:
        super(OTX_Collector, self).__init__(ip)
        self._session = requests.Session()
        self._session_headers: dict = {'X-OTX-API-KEY': OTX_KEY}
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
