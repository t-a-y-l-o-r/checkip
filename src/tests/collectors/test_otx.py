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
    actual = parser.parse(raw_report)

    expected_keys = {
        "header",
        "report",
        "additional_information"
    }
    actual_keys = set(actual.keys())
    assert expected_keys == actual_keys


def test_parser_parse_empty(parser: OTX_Parser) -> None:
    raw_report = {}
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
    actual = parser._build_report(raw_report)

    expected = None
    assert expected == actual


def test_parser_build_report_empty(parser: OTX_Parser) -> None:
    raw_report = {}
    actual = parser._build_report(raw_report)

    expected = None
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

