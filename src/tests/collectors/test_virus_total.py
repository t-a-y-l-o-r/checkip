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


#       ===================
#           Parser
#       ===================

def test_parser_parse_keys(parser, raw_report):
    report = parser.parse(raw_report)

    keys = [
        "header",
        "report",
        "additional_information"
    ]
    for key in keys:
        assert key in report


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

