import pytest

from collectors.otx import (
    OTX_Parser
)


@pytest.fixture
def parser() -> OTX_Parser:
    return OTX_Parser()


@pytest.fixture
def raw_report() -> dict:
    return {
        "general": {},
        "reputation": {},
        "url_list": {}
    }

#       ======================================
#           parser.parse
#       ======================================

def test_parser_parse_none(parser: OTX_Parser) -> None:
    raw_report = None
    actual = parser.parse(raw_report) # type: ignore

    expected_keys = {
        "header",
        "report",
        "additional_information"
    }
    actual_keys = set(actual.keys())
    assert expected_keys == actual_keys


def test_parser_parse_empty(parser: OTX_Parser) -> None:
    raw_report: dict = dict()
    actual = parser.parse(raw_report)

    expected_keys = {
        "header",
        "report",
        "additional_information"
    }
    actual_keys = set(actual.keys())
    assert expected_keys == actual_keys


def test_parser_parse_good(parser: OTX_Parser, raw_report: dict) -> None:
    actual = parser.parse(raw_report)

    expected_keys = {
        "header",
        "report",
        "additional_information"
    }
    actual_keys = set(actual.keys())
    assert expected_keys == actual_keys


#       ======================================
#           parser._empty_report
#       ======================================

def test_parser_empty_report(parser: OTX_Parser) -> None:
    actual = parser._empty_report()

    expected_keys = {
        "header",
        "report",
        "additional_information"
    }
    actual_keys = set(actual.keys())
    assert expected_keys == actual_keys


#       ======================================
#           parser._build_report
#       ======================================


def test_parser_build_report_none(parser: OTX_Parser) -> None:
    raw_report = None
    actual = parser._build_report(raw_report) # type: ignore

    expected: dict = dict()
    assert expected == actual


def test_parser_build_report_empty(parser: OTX_Parser) -> None:
    raw_report: dict = dict()
    actual = parser._build_report(raw_report)

    expected: dict = dict()
    assert expected == actual


def test_parser_build_report_good(parser: OTX_Parser, raw_report: dict) -> None:
    actual = parser._build_report(raw_report)

    expected_keys = {
        "asn",
        "Country",
        "City",
        "Threat Score",
        "Type"
    }
    actual_keys = set(actual.keys())
    assert expected_keys == actual_keys

#       ======================================
#           parser._build_add_info
#       ======================================


def test_parser_build_add_info_none(parser: OTX_Parser) -> None:
    raw_report = None
    actual = parser._build_add_info(raw_report, raw_report) # type: ignore

    expected_keys = {
        "reputation",
        "url_list"
    }
    actual_keys = set(actual.keys())
    assert expected_keys == actual_keys


def test_parser_build_add_info_empty(parser: OTX_Parser) -> None:
    raw_report: dict = dict()
    actual = parser._build_add_info(raw_report, raw_report) # type: ignore

    expected_keys = {
        "reputation",
        "url_list"
    }
    actual_keys = set(actual.keys())
    assert expected_keys == actual_keys


def test_parser_build_add_info_good(parser: OTX_Parser, raw_report: dict) -> None:
    actual = parser._build_add_info(raw_report["reputation"], raw_report["url_list"])

    expected_keys = {
        "reputation",
        "url_list"
    }
    actual_keys = set(actual.keys())
    assert expected_keys == actual_keys


#       ======================================
#           parser._parse_reputation
#       ======================================


def test_parser_parse_reputation_none(parser: OTX_Parser) -> None:
    raw_report = None
    actual = parser._parse_reputation(raw_report) # type: ignore

    expected: dict = dict()
    assert expected == actual


def test_parser_parse_reputation_empty(parser: OTX_Parser) -> None:
    raw_report: dict = dict()
    actual = parser._parse_reputation(raw_report) # type: ignore

    expected: dict = dict()
    assert expected == actual


def test_parser_parse_reputation_good(parser: OTX_Parser, raw_report: dict) -> None:
    actual = parser._parse_reputation(raw_report)

    expected_keys = {
        "threat_score",
        "type_of_activities",
        "last_seen",
        "domains"
    }
    actual_keys = set(actual.keys())
    assert expected_keys == actual_keys

#       ======================================
#           parser._url_list
#       ======================================


def test_parser_parse_url_list_none(parser: OTX_Parser) -> None:
    raw_report = None
    actual = parser._parse_url_list(raw_report) # type: ignore

    expected: list = []
    assert expected == actual


def test_parser_parse_url_list_empty(parser: OTX_Parser) -> None:
    raw_report: dict = dict()
    actual = parser._parse_url_list(raw_report) # type: ignore

    expected: list = []
    assert expected == actual


def test_parser_parse_url_list_good(parser: OTX_Parser, raw_report: dict) -> None:
    raw_url_list = raw_report.get("url_list", [])
    actual = parser._parse_url_list(raw_url_list)

    flattened_url_list = [url["domain"] for url in raw_url_list]

    valid_domain = lambda domain: domain != "" and domain is not None
    expected = list(filter(valid_domain, flattened_url_list))

    assert expected == actual

