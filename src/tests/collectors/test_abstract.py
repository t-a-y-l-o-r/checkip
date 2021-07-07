# Ensures the abstract interface for the `collectors` module
# is actually abstract
#
import pytest
import asyncio
from collectors import collectors



#       ===================
#         Dummy Classes
#       ===================

class Dummy_Caller(collectors.Collector_Caller):
    def __init__(self, key):
        self.key = key

    async def call(self) -> dict:
        await asyncio.sleep(0.1)
        return {}


class Dummy_Parser(collectors.Collector_Parser):
    def __init__(self):
        pass

    def parse(self, report: dict) -> dict:
        return {}

#       ===================
#           Tests
#       ===================

def test_collector_parser_construction_fail():
    with pytest.raises(TypeError):
        collectors.Collector_Parser()


def test_collector_caller_construction_fail():
    with pytest.raises(TypeError):
        collectors.Collector_Caller()


def test_collector_core_construction_fail():
    with pytest.raises(TypeError):
        collectors.Collector_Core()


def test_collector_construction_no_args():
    with pytest.raises(ValueError):
        collectors.Collector()


def test_collector_construction_with_key():
    keys = [
        "alshdkadjasldshdnasd",
        1234521412
    ]
    for key in keys:
        col = collectors.Collector(key)

        with pytest.raises(AttributeError):
            col._caller

        with pytest.raises(AttributeError):
            col._parser


def test_collector_construction_with_key_and_caller():
    keys = [
        "alshdkadjasldshdnasd",
        1234521412
    ]
    for key in keys:
        col = collectors.Collector(key, caller=Dummy_Caller)

        col._caller

        with pytest.raises(AttributeError):
            col._parser


def test_collector_construction_with_key_and_parser():
    keys = [
        "alshdkadjasldshdnasd",
        1234521412
    ]
    for key in keys:
        col = collectors.Collector(key, parser=Dummy_Parser)

        with pytest.raises(AttributeError):
            col._caller

        col._parser


@pytest.mark.asyncio
async def test_collector_report():
    keys = [
        "alshdkadjasldshdnasd",
        1234521412
    ]
    for key in keys:
        col = collectors.Collector(key, caller=Dummy_Caller, parser=Dummy_Parser)
        report = await col.report()


