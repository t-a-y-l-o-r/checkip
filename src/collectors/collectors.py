from abc import ABC, abstractmethod
from typing import Type
from enum import Enum, unique
import requests
import json
import os
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

VIRUS_TOTAL_KEY = os.environ["VT_KEY"]
OTX_KEY = os.environ["OTX_KEY"]

'''
            ================
                Types
            ================
'''

@unique
class Types(Enum):
    VIRUS_TOTAL = 1
    OTX = 2
    ROBTEX = 3

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
    def of(self, type: Types, ip: str=None)-> "Collector":
        pass

class Collector_Factory(Abstract_Collector_Factory):
    '''
    Concrete factory for the collectors defined within this module
    '''
    def of(self, typeOf: Types, ip: str=None) -> "Collector":
        if typeOf == Types.VIRUS_TOTAL:
            return Virus_Total_Collector(ip=ip)
        elif typeOf == Types.OTX:
            return OTX_Collector(ip=ip)
        elif typeOf == Types.ROBTEX:
            return Robtex_Collector(ip=ip)
        else:
            raise TypeError(f"Unknown collector type of {type(typeOf)}")

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
    def __init__(self, ip: str=None):
        self.ip = ip

    @abstractmethod
    def header(self):
        pass

    @abstractmethod
    def report(self):
        pass

'''
            ================
              Virus Total
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
    def __init__(self, ip=None):
        super(Virus_Total_Collector, self).__init__(ip)
        self._session = requests.Session()
        self._session.headers.update({'x-apikey': VIRUS_TOTAL_KEY})
        self._header = None
        self._report = None

    def header(self):
        if self._header is None:
            self._call_and_parse_all()
        return self._header

    def report(self):
        if self._report is None:
            self._call_and_parse_all()
        return self._report

    def _call_and_parse_all(self):
        response = self._call("ip")
        self._parse_ip(response)
        response = self._call("resolutions")
        self._parse_resolutions(response)

        self._header = "".join([
            self._header,
            "\n",
            self._checked,
            "\n",
            self._owner,
            "\n",
            self._stats
        ])
        self._report["sites"] = self._sites
        self._report = json.dumps(self._report, sort_keys=True, indent=4)

    def _call(self, call_type="ip", limit=20):
        '''
        Call out to a given enpoint based on the call_type.

        If call_type is not set then the default endpoint is selcted.
        Otherwise resolutions is called if selected.
        As a fail safe the un-implemented selections the
        function will throw a ValueError if it can't parse the
        call_type.

        Returns the reponse if it determines it is valid
        '''
        if call_type is None:
            raise ValueError("Call type cannot be none")
        if call_type == "ip":
            call_type = ""
            limit = ""
        else:
            call_type = "/{}".format(call_type)
            limit = "?limit={0}".format(limit)
        report_url = [
            'https://www.virustotal.com/',
            'api/v3/ip_addresses/',
            self.ip,
            call_type,
            limit,
        ]
        report_url = "".join(report_url)
        response = self._session.get(report_url)

        code = response.status_code
        if code == 200:
            return response
        elif code == 204:
            raise ValueError("Virustotal rate limit reached!")
        else:
            raise ValueError(
                "Server reply: {0} Message: {1}".
                format(code, response.text))

    def _parse_ip(self, base):
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
        json_message = base.json()
        data = json_message.get("data")
        attributes = data.get("attributes")
        owner = attributes.get("as_owner")
        owner = "[Owner] {0}".format(owner)

        header = "\t[Virus Total]\n"
        checked = "[Unknown] ✅"
        stats = ""
        analysis_json = attributes.get("last_analysis_stats")

        for key in analysis_json.keys():
            value = analysis_json.get(key)
            stats += f"[{key}] {value}\n"
            if key == "malicious" and int(value) > 0:
                checked = "[malicious] ❌"
            elif key == "suspicious" and int(value) > 0:
                checked = "[suspicious] ❓"

        analysis_json = attributes.get("last_analysis_results")
        for key in analysis_json.keys():
            agency = analysis_json.get(key)
            result = agency.get("result")
            if result != "clean" and result != "unrated":
                report[(f"{key}")] = agency
        self._header = header
        self._checked = checked
        self._owner = owner
        self._stats = stats
        self._report = report

    def _parse_resolutions(self, response):
        # get relations data
        sites = []
        relations_response = response.json()
        data = relations_response.get("data")
        for site_data in data:
            attributes = site_data.get("attributes")
            host = attributes.get("host_name")
            sites.append(host)
        self._sites = sites


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
    def __init__(self, ip=None):
        super(OTX_Collector, self).__init__(ip)
        self._session = requests.Session()
        self._session.headers.update({'X-OTX-API-KEY': OTX_KEY})
        self._header = None
        self._report = None
        self._general = None
        self._reputation = None
        self._url_list = None

    def header(self):
        if self._header is None:
            self._call_and_parse_all()
        return self._header

    def report(self):
        if self._report is None:
            self._call_and_parse_all()
        return self._report

    def _call_and_parse_all(self):
        # call everything and parse individually
        general = self._call(call_type="general")
        self._parse_general(general)
        reputation = self._call(call_type="reputation")
        self._parse_reputation(reputation)
        url_list = self._call(call_type="url_list")
        self._parse_urls(url_list)
        # convert into human readable
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
        self._report = {
            "last_seen": self._reputation.get("last_seen"),
            "type_of_activities": self._reputation.get("type_of_activities"),
            "domains": self._url_list
        }
        self._report = json.dumps(
            self._report,
            indent=4,
            sort_keys=True
        )

    def _call(self, call_type=None):
        '''
        Call out to a given enpoint based on the call_type.
        provides a response if possible
        '''
        endpoint = "https://otx.alienvault.com/api/v1/indicators/IPv4/"
        if call_type is not None:
            report_url = "{0}/{1}/{2}".format(endpoint, self.ip, call_type)
            response = self._session.get(report_url)

            code = response.status_code
            if code == 200:
                return response
            elif code == 204:
                raise ValueError("OTX rate limit reached!")
            else:
                raise ValueError(
                    "Server reply: {0} Message: {1}".
                    format(code, response.text))
        else:
            raise ValueError("Invalid call type {0}".format(call_type))

    def _parse_general(self, response):
        json = response.json()
        asn = json.get("asn")
        country_name = json.get("country_name")
        city = json.get("city")
        self._general = {
            "asn": asn,
            "country_name": country_name,
            "city": city,
        }

    def _parse_reputation(self, response):
        json = response.json()
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
        self._reputation = {
            "threat_score": threat_score,
            "type_of_activities": type_of_activities,
            "last_seen": last_seen,
            "domains": domains
        }

    def _parse_urls(self, response):
        json = response.json()
        self._url_list = []
        urls = json.get("url_list")
        domain = ""
        for url in urls:
            domain = url.get("domain")
            if domain != "" and domain is not None:
                self._url_list.append(domain)


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
    def __init__(self, ip=None):
        super(Robtex_Collector, self).__init__(ip)
        self._session = requests.Session()
        self._header = None
        self._report = None

    def header(self):
        if self._header is None:
            self._call_and_parse_all()
        return self._header

    def report(self):
        if self._report is None:
            self._call_and_parse_all()
        return self._report

    def _call_and_parse_all(self):
        call_dict = self._call().json()
        self._header = "".join([
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
        self._report = json.dumps({
            "passiveDNS" : call_dict.get("pas"),
            "activeDNS": call_dict.get("act")
        }, indent=4, sort_keys=True)

    def _call(self, call_type="ip"):
        '''
        Calls out to the robtext end point
        https://freeapi.robtex.com/ipquery/{ip}

        Providing and attempting to route the response
        '''
        if call_type is None:
            raise ValueError("Invalid call type {0}".format(call_type))
        endpoint = "https://freeapi.robtex.com/"
        if call_type == "ip":
            endpoint = "{0}/ipquery/{1}".format(endpoint, self.ip)
        response = self._session.get(endpoint)
        code = response.status_code
        if code == 200:
                return response
        elif code == 204:
            raise ValueError("OTX rate limit reached!")
        else:
            raise ValueError(
                "Server reply: {0} Message: {1}".
                format(code, response.text))

