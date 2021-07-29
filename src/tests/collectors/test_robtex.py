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
    keys = [
        "header",
        "report",
        "additional_information"
    ]
    report = parser.parse(raw_report)

    for key in keys:
        assert key in report


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

    output_keys = [
        "header",
        "report",
        "additional_information"
    ]

    report = parser.parse(report_with_bad_keys)

    for key in output_keys:
        assert key in report


#       ======================================
#           parser._build_error_report
#       ======================================
