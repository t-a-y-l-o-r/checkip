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


