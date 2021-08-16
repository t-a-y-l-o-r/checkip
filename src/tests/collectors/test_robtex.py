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
        "pas": [
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
    should_fail: list = [
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

        report = parser._build_error_report(error)  # type: ignore
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

    report = parser._build_valid_report(raw_report) # type: ignore
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


#       ======================================
#        parser._build_additional_information
#       ======================================


def test_parser_build_add_info_none_fail(parser: Robtex_Parser) -> None:
    with pytest.raises(AssertionError):
        report = parser._build_report(None) # type: ignore


def test_parser_build_add_info_bad_keys(parser: Robtex_Parser) -> None:
    report = {
        "some_key": "value",
        "asldhajsldhals": "1232103",
    }
    expected_keys = {
        "passive_dns",
        "active_dns"
    }
    report = parser._build_additional_information(report)
    actual_keys = set(report.keys())

    assert expected_keys == actual_keys


def test_parser_build_add_info_valid(parser: Robtex_Parser, raw_report: dict) -> None:
    expected_keys = {
        "passive_dns",
        "active_dns"
    }

    report = parser._build_additional_information(raw_report)
    actual_keys = set(report.keys())

    assert expected_keys == actual_keys


#       ======================================
#        parser._build_passive_dns_list
#       ======================================

def test_praser_build_passive_dns_list_none(parser: Robtex_Parser) -> None:
    expected: list = []
    actual = parser._build_passive_dns_list(None) # type: ignore

    assert expected == actual


def test_praser_build_passive_dns_list_valid(parser: Robtex_Parser, raw_report: dict) -> None:
    passive_dns = raw_report["pas"]
    site_key = "o"
    expected = [dict_pair[site_key] for dict_pair in passive_dns]

    actual = parser._build_passive_dns_list(passive_dns)

    assert expected == actual



#       ======================================
#        parser._build_dns_list
#       ======================================

def test_praser_build_dns_list_none(parser: Robtex_Parser) -> None:
    expected: list = []
    actual = parser._build_dns_list(None, None) # type: ignore

    assert expected == actual


def test_praser_build_active_dns_list_valid(parser: Robtex_Parser, raw_report: dict) -> None:
    active_dns = raw_report["act"]
    site_key = "o"
    expected = [dict_pair[site_key] for dict_pair in active_dns]

    actual = parser._build_dns_list(active_dns, site_key)

    assert expected == actual


