import pytest

from collectors.robtex import (
    Robtex_Parser
)


@pytest.fixture
def raw_report() -> dict:
    return {
        "city": "Mountain View",
        "country": "United States",
        "as": 15169,
        "asname": "Google Google, Inc",
        "asdesc": "NeuStar NeuStar, Inc",
        "whoisdesc": "Google LLC (GOGL)",
        "routedesc": "SP_BEEKSFX",
        "bgproute": "8.8.8.0/24",
        "act": [
            {
              "o": "50661.red",
              "t": 1505943755
            },
            {
              "o": "flowerpowermosquito.com",
              "t": 1493294473
            }
        ],
        "acth": [
            {
              "o": "50661.red",
              "t": 1505943755
            },
            {
              "o": "flowerpowermosquito.com",
              "t": 1493294473
            }
        ],
    }


@pytest.fixture
def parser() -> Robtex_Parser:
    return Robtex_Parser()


#       ======================================
#           parser.parse
#       ======================================

def test_parser_parse_keys(parser: Robtex_Parser, raw_report: dict) -> None:
    expected_keys = {
        "header",
        "report",
        "additional_information"
    }

    report = parser.parse(raw_report)
    actual_keys = set(report.keys())

    assert expected_keys == actual_keys


def test_parser_parse_empty(parser: Robtex_Parser) -> None:
    should_fail = [
        None,
        {}
    ]
    for bad_report in should_fail:
        with pytest.raises(AssertionError):
            report = parser.parse(bad_report)


def test_parser_parse_bad_keys(parser: Robtex_Parser) -> None:
    report_with_bad_keys = {
        "asdlhalsdjas": [],
        "asdhaljsdas": [],
        "123123": 123123
    }

    expected_keys = {
        "header",
        "report",
        "additional_information"
    }

    report = parser.parse(report_with_bad_keys)
    actual_keys = set(report.keys())

    assert expected_keys == actual_keys


def test_parser_parse_error_message(parser: Robtex_Parser) -> None:
    error_report = {
        "ERROR": "some error message"
    }

    expected_keys = {
        "header",
        "report",
        "additional_information"
    }

    report = parser.parse(error_report)
    actual_keys = set(report.keys())

    assert expected_keys == actual_keys

    actual = report["report"]
    expected = error_report["ERROR"]

    assert expected == actual


#       ======================================
#           parser._build_error_report
#       ======================================

def test_parser_build_error_report(parser: Robtex_Parser) -> None:
    error_messages = [
        "timeout",
        "other message that have failed",
        None
    ]

    expected_keys = {
        "report",
        "additional_information"
    }

    for error in error_messages:

        report = parser._build_error_report(error)
        actual_keys = set(report.keys())

        assert expected_keys == actual_keys

        add_info = report["additional_information"]
        assert None == add_info


#       ======================================
#           parser._build_valid_report
#       ======================================

def test_parser_build_valid_report(parser: Robtex_Parser, raw_report: dict) -> None:
    expected_keys = {
        "report",
        "additional_information"
    }

    report = parser._build_valid_report(raw_report)
    actual_keys = set(report.keys())

    assert expected_keys == actual_keys


#       ======================================
#           parser._build_report
#       ======================================

def test_parser_build_report(parser: Robtex_Parser, raw_report: dict) -> None:
    expected_keys = {
        "asname",
        "whois",
        "bgproute",
        "routedesc",
        "country",
        "city"
    }

    report = parser._build_report(raw_report)
    actual_keys = set(report.keys())

    assert expected_keys == actual_keys


