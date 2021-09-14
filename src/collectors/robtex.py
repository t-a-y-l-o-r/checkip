from typing import (
    Optional,
)

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
        self._header_key = "header"

        self._report_key = "report"
        self._add_info_key = "additional_information"

        self._error_key = "ERROR"


    def parse(self, raw_report: dict) -> dict:
        assert raw_report
        error_message = raw_report.get(self._error_key, None)

        report = self._build_error_report(error_message) if error_message else \
                 self._build_valid_report(raw_report)

        report[self._header_key] = self._header
        return report


    def _build_error_report(self, error_message: str) -> dict:
        return {
            self._report_key : error_message,
            self._add_info_key: None
        }


    def _build_valid_report(self, report: dict) -> dict:
        return {
            self._report_key: self._build_report(report),
            self._add_info_key: self._build_additional_information(report)
        }


    def _build_report(self, call_dict: dict) -> dict:
        assert call_dict is not None
        report = {
                "asname": call_dict.get("asname", None),
                "whois": call_dict.get("whoisdesc", None),
                "bgproute": call_dict.get("bgproute", None),
                "routedesc": call_dict.get("routedesc", None),
                "country": call_dict.get("country", None),
                "city": call_dict.get("city", None),
        }
        return report


    def _build_additional_information(self, call_dict: dict) -> dict:
        assert call_dict is not None

        passive_dict = call_dict.get("pas", None)
        passive_list = self._build_passive_dns_list(passive_dict)

        active_dict = call_dict.get("act", None)
        active_list = self._build_active_dns_list(active_dict)

        return {
            "passive_dns": passive_list,
            "active_dns": active_list
        }


    def _build_passive_dns_list(self, passive_dict: dict, site_key: str="o") -> list:
        return self._build_dns_list(passive_dict, site_key)


    def _build_active_dns_list(self, active_dict: dict, site_key: str="o") -> list:
        return self._build_dns_list(active_dict, site_key)


    def _build_dns_list(self, dns_dict: dict, site_key: str) -> list:
        if dns_dict:
            return [dict_pair[site_key] for dict_pair in dns_dict]
        else:
            return []


class Robtex_Caller(Collector_Caller):
    def __init__(self, key: str) -> None:
        super().__init__(key)
        self._base_endpoint: str = "https://freeapi.robtex.com"


    async def call(self, ip: str) -> dict:
        return await self._call(ip)


    async def _call(self, ip: str) -> dict:
        '''
        Calls out to the robtext end point
        https://freeapi.robtex.com/ipquery/{ip}

        Providing and attempting to route the response
        '''
        assert ip
        endpoint = self._build_endpoint(ip)

        async with aiohttp.ClientSession() as session:
            async with session.get(endpoint) as response:
                code = response.status
                if code == 200:
                    return await response.json()
                elif code == 429:
                    return IOError("Robtex rate limit reached")
                elif code == 502:
                    return IOError("Robtex bad gateway")
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


    def _build_endpoint(self, ip) -> str:
        return "".join([
            self._base_endpoint,
            "/ipquery/",
            ip
        ])


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


