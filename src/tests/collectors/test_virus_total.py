# Tests the VirusTotal implmentation of the collector class

import pytest

from collectors.virus_total import (
    VT_Parser
)

#       ===================
#           Fixtures
#       ===================
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

#       ===================
#           Parser
#       ===================

def test_parser_construction():
    parser = VT_Parser()

def test_parser_parse_keys(raw_report):
    parser = VT_Parser()
    report = parser.parse(raw_report)

    keys = [
        "header",
        "report",
        "additional_information"
    ]
    for key in keys:
        assert key in report
