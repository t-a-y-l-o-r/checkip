#!/usr/bin/env python3
from collectors.async_collectors import Collector, Collector_Types, Collector_Factory
from typing import Any, Dict, KeysView, List, Tuple
import multiprocessing as multi
from report import report
from reader import reader
from io import StringIO
import multiprocessing
from ui import ui
import traceback
import cProfile
import logging
import json
import sys

import time
import asyncio

'''
A set of python tools used to generate securirty reports on flagged ips.
The ip's will be passed by the user using flags

Test IPs:
### clean ###
8.8.8.8

### relations ###
23.227.38.65
192.5.6.30
95.85.34.111

### Undetected ###
198.45.140.255
166.164.29.88

'''

#   ========================================================================
#                       Table of Contents
#   ========================================================================
# 1. Globals
# 2. IP_Checker
# 3. The `main` for the pipeline
# 4. Collector Process
# 5. Record
#
#
#
#   ========================================================================
#                       Description
#   ========================================================================
# This module is the "core" of the program.
#
# This file should handle any inter-module communication, as well as managing
# the main data-pipeline for the entire system. You can think of it as the
# back-bone.
#

#   ========================================================================
#                       Globals
#   ========================================================================

PROCESSES = 1
logging.basicConfig(
    filename=".log",
    filemode="w",
    format="%(name)s - %(levelname)s - %(message)s",
    level=logging.DEBUG)
logger = logging.getLogger("ipchecker")

#   ========================================================================
#                       IP_Checker
#   ========================================================================

class IP_Checker():
    def __init__(self):
        self.ui = ui.UI()
        self.report = report.Report_Builder()
        self.factory = Collector_Factory()
        self._collectors = None
        self.reader = reader.Reader()
        self.ips = list()
        logger.info("IP_Checker finished init")

    @property
    def collectors(self):
        '''
        Manages the collectors definition
        '''
        if self._collectors:
            return self._collectors
        else:
            col_list = []
            for col_type in Collector_Types:
                col_list.append(
                    self.factory.of(col_type)
                )
            self._collectors = col_list
            return self._collectors

#   ========================================================================
#                       Main Stuff
#   ========================================================================

    def main(self) -> None:
        '''
        The main function. Manages all of the sub-modules,
        and the ordering in which they will execute.
        Will attempt to validate that all necessary setup
        has completed.
        '''
        if self.ui.ip is not None:
            self.ips.append(self.ui.ip)
        elif self.ui.ip_file is not None:
            self.ips = self.reader.read_input_file(self.ui.ip_file)
        else:
            logger.warning("No -if or -ip flag given")
            self.ui.display_help()
            sys.exit(1)

        # ensure report is empty
        self.report.create_report()
        # check to see if a record exists, else create it
        record_ips = self.reader.read_record("./record.json")
        if record_ips is {}:
            self.report.create_record()

        # check if forcing all ips or not
        actual_ips = None
        if self.ui.force:
            actual_ips = self.filter_record_ips(
                self.ips,
                record_ips,
                display=False
            )
            self.main_loop(self.ips, self.collectors)
        else:
            actual_ips = self.filter_record_ips(self.ips, record_ips)
            self.main_loop(actual_ips.keys(), self.collectors)

        logger.info("Recording ips")
        # merge dicts and record
        self.record_ips({**actual_ips, **record_ips})


#   ========================================================================
#                       Record Stuff
#   ========================================================================

    def record_ips(self, ips: Dict[Any, Any]) -> None:
        self.report.write_record(
            json.dumps(
                ips,
                indent=4,
                sort_keys=True
            )
        )

    def filter_record_ips(
        self,
        given: Dict[str, str],
        record: Dict[str, str],
        display: bool=True
    ) -> Dict:
        '''
        Will attempt to filter out the ips from the given
        set which are already in the recorded set.
        Args:
            given - the ips which were provided by the user
            record - the ips which have already been scanned
        Return:
            the ips which are to be scanned
        '''
        keys = record.keys()
        unique_ips = dict()
        excluded = list()
        for i, ip in enumerate(given):
            if ip not in keys:
                unique_ips[ip] =  {"notes": "N/A"}
            else:
                excluded.append({ip: record[ip]})
        if len(excluded) > 0 and display:
            self.ui.display_excluded_ips(excluded)
        return unique_ips

#   ========================================================================
#                       Collector Process Stuff
#   ========================================================================

    def main_loop(self, ips_list, collectors):
        for ip in ips_list:
            event_loop = asyncio.get_event_loop()
            event_loop.run_until_complete(
                self.async_pipeline(ip, collectors)
            )

    async def async_pipeline(self, ip, collectors):
        report_funcs = []
        for collector in collectors:
            collector.ip = ip
            report_funcs.append(collector.header())
            report_funcs.append(collector.report())

        await asyncio.gather(*report_funcs)
        for collector in collectors:
            header = await collector.header()
            report = await collector.report()
            print(f"[*] header: {header}")
            print(f"[*] report: {report}")


if __name__ == "__main__":
    # cProfile.run("main_loop()")

    start = time.time()
    checker = IP_Checker()
    checker.main()
    end = time.time()
    diff = end - start
    print(f"[*] Total time: {diff}")
