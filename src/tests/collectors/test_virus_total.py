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
                        }
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
#           parser._last_stats
#       ======================================


def test_parser_last_stats_keys(parser, last_analysis_stats):
    stats = parser._last_stats(last_analysis_stats)

    keys = [
        "harmless",
        "malicious",
        "suspicious",
        "undetected",
        "timeout"
    ]
    for key in keys:
        assert key in stats


def test_parser_last_stats_keys_fails(parser, last_analysis_stats):
    stats = parser._last_stats(last_analysis_stats)

    keys = [
        "harmless12-1211212j",
        "maasdljashdljad",
        "000000",
        -1
    ]
    for key in keys:
        assert key not in stats


def test_parser_overall_status_defaults(parser):
    default = VT_Status_Types.harmless.value
    symbol = VT_Status_Symbols[default]
    as_status = f"{default} {symbol}"
    assert as_status == parser._determine_overall_status({})


def test_parser_overall_status(parser):
    default = VT_Status_Types.harmless.value
    symbol = VT_Status_Symbols[default]
    as_status = f"{default} {symbol}"

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


def test_parser_last_results(parser, last_analysis_results):
    expected = {}
    clean = "clean"
    unrated = "unrated"

    for stats in last_analysis_results.keys():
        agency = last_analysis_results[stats]
        result = agency["result"]
        if result != clean and result != unrated:
            expected[stat] = agency

    actual = parser._last_results(last_analysis_results)

    assert expected == actual


def test_parser_resolutions(parser, resolutions):
    expected = []
    data = resolutions["data"]

    for site_data in data:
        attributes = site_data["attributes"]
        host = attributes["host_name"]
        expected.append(host)

    actual = parser._parse_resolutions(resolutions)

    assert expected == actual


def test_parser_resolutions_empty(parser):
    resolutions = {}
    expected = []
    actual = parser._parse_resolutions(resolutions)

    assert expected == actual


def test_parser_resolutions_empty(parser):
    resolutions = None
    expected = []
    actual = parser._parse_resolutions(resolutions)

    assert expected == actual

