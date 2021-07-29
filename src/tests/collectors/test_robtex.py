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
        "bgproute": "8.8.8.0/24"
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

#       ======================================
#           parser.parse
#       ======================================

def test_parser_parse_keys(parser, raw_report) -> None:
    return None
