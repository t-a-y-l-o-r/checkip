# Tests the VirusTotal implmentation of the collector class

import pytest

from collectors.virus_total import (
    VT_Parser,
    VT_Status_Types,
    VT_Status_Symbols
)

#       ===================
#           Fixtures
#       ===================

@pytest.fixture
def parser() -> VT_Parser:
    return VT_Parser()

@pytest.fixture
def raw_report() -> dict:
    return {
        "ip": {
            "data": {
                "attributes": {
                    "as_owner": [],
                    "last_analysis_stats": {
                      "harmless": 1,
                      "malicious": 0,
                      "suspicious": 0,
                      "undetected": 0,
                      "timeout": 0
                    },
                    "last_analysis_results": {
                        "Google Safebrowsing": {
                          "category": "harmless",
                          "result": "clean",
                          "method": "blacklist",
                          "engine_name": "Google Safebrowsing"
                        },
                        "Facebook": {
                          "category": "malicious",
                          "result": "not so clean",
                          "method": "blacklist",
                          "engine_name": "Safebrowsing"
                        },

                    }
                }
            }
        },
        "resolutions": {
            "data": [
                {
                  "attributes": {
                    "host_name": "learn-quran.site",
                  },
                }
            ]
        }
    }

@pytest.fixture
def ip_report(raw_report) -> dict:
    return raw_report["ip"]

@pytest.fixture
def resolutions(raw_report) -> dict:
    return raw_report["resolutions"]


@pytest.fixture
def last_analysis_stats(raw_report) -> dict:
    ip_report = raw_report["ip"]
    data = ip_report["data"]
    attributes = data["attributes"]
    analysis_json = attributes["last_analysis_stats"]

    return analysis_json


@pytest.fixture
def last_analysis_results(raw_report) -> dict:
    ip_report = raw_report["ip"]
    data = ip_report["data"]
    attributes = data["attributes"]
    analysis_json = attributes["last_analysis_results"]

    return analysis_json


#       ======================================
#           parser.parse
#       ======================================

def test_parser_parse_keys(parser, raw_report):
    report = parser.parse(raw_report)

    keys = [
        "header",
        "report",
        "additional_information"
    ]
    for key in keys:
        assert key in report

def test_parser_parse_is_none(parser):
    with pytest.raises(AssertionError):
        parser.parse(None)

#       ======================================
#           parser._parse_ip
#       ======================================

def test_parser_parse_ip_none(parser):
    ip_report = None
    with pytest.raises(AssertionError):
        parser._parse_ip(ip_report)


def test_parser_parse_ip_empty(parser):
    ip_report = {}
    with pytest.raises(AssertionError):
        parser._parse_ip(ip_report)


def test_parser_parse_ip_correct_keys(parser, ip_report):
    keys = [
        "header",
        "report",
        "additional_information"
    ]

    ip_response = parser._parse_ip(ip_report)

    for key in keys:
        assert key in ip_response


def test_parser_parse_ip_no_data(parser):
    ip_report = {
        "not_data": None
    }

    with pytest.raises(KeyError):
        parser._parse_ip(ip_report)


def test_parser_parse_ip_no_attributes(parser):
    ip_report = {
        "data": {
            "not_attributes": None
        }
    }

    with pytest.raises(KeyError):
        parser._parse_ip(ip_report)


def test_parser_parse_ip_no_as_owner(parser):
    ip_report = {
        "data": {
            "attributes": {
                "not_as_owner": None
            }
        }
    }

    with pytest.raises(KeyError):
        parser._parse_ip(ip_report)


def test_parser_parse_ip_no_last_analysis_stats(parser):
    ip_report = {
        "data": {
            "attributes": {
                "not_last_analysis_stats": None
            }
        }
    }

    with pytest.raises(KeyError):
        parser._parse_ip(ip_report)


def test_parser_parse_ip_no_last_analysis_results(parser):
    ip_report = {
        "data": {
            "attributes": {
                "not_last_analysis_results": None
            }
        }
    }

    with pytest.raises(KeyError):
        parser._parse_ip(ip_report)


#       ======================================
#           parser._determine_overall_status
#       ======================================


def test_parser_overall_status_empty_dict(parser):
    with pytest.raises(AssertionError):
        parser._determine_overall_status({})


def test_parser_overall_status_none_dict(parser):
    with pytest.raises(AssertionError):
        parser._determine_overall_status(None)

def test_parser_overall_status_zero_scans(parser):
    default_type = VT_Status_Types.harmless.value
    default_symbol = VT_Status_Symbols[default_type]
    expected = f"{default_type} {default_symbol}"

    empty_stats = {
        "harmless": 0,
        "malicious": 0,
        "suspicious": 0,
        "undetected": 0,
        "timeout": 0
    }
    actual = parser._determine_overall_status(empty_stats)

    assert expected == actual


def test_parser_overall_status(parser):
    stats_list = [
        {
            "input": {
                "harmless": 1,
                "malicious": 0,
                "suspicious": 0,
                "undetected": 0,
                "timeout": 0
            },
            "result": "harmless ✅"
        },
        {
            "input": {
                "harmless": 10,
                "malicious": 20,
                "suspicious": 0,
                "undetected": 1,
                "timeout": 1,
            },
            "result": "malicious ❌"
        },
        {
            "input": {
                "harmless": 10,
                "malicious": 20,
                "suspicious": 30,
                "undetected": 1,
                "timeout": 1,
            },
            "result": "suspicious ❌"
        },
        {
            "input": {
                "harmless": 10,
                "malicious": 20,
                "suspicious": 30,
                "undetected": 40,
                "timeout": 1,
            },
            "result": "undetected ❓"
        },
        {
            "input": {
                "harmless": 10,
                "malicious": 20,
                "suspicious": 30,
                "undetected": 40,
                "timeout": 100,
            },
            "result": "timeout ❓"
        },
    ]

    for stats in stats_list:
        status_stats = stats["input"]
        expected_result = stats["result"]
        actual_result = parser._determine_overall_status(status_stats)

        assert expected_result == actual_result


#       ======================================
#           parser._last_results
#       ======================================


def test_parser_last_results(parser, last_analysis_results):
    expected = {}
    clean = "clean"
    unrated = "unrated"

    dirty = lambda site: site[1]["result"] != "clean" and site[1]["result"] != "unrated"
    expected = dict(filter(dirty, last_analysis_results.items()))
    actual = parser._last_results(last_analysis_results)

    assert expected == actual


#       ======================================
#           parser._get_sites_from_resolutions
#       ======================================


def test_get_sites_from_resolutions(parser, resolutions):
    expected = [site["attributes"]["host_name"] for site in resolutions["data"]]
    actual = parser._get_sites_from_resolutions(resolutions)

    assert expected == actual


def test_parser_get_sites_from_resolutions_empty(parser):
    resolutions = {}
    expected = []
    actual = parser._get_sites_from_resolutions(resolutions)

    assert expected == actual


def test_parser_get_sites_from_resolutions_none(parser):
    resolutions = None
    expected = []
    actual = parser._get_sites_from_resolutions(resolutions)

    assert expected == actual


