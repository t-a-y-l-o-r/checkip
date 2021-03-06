#!/usr/bin/env python3
from collectors.collectors import Collector, Collector_Types, Collector_Factory
from multiprocessing.connection import Connection
from typing import Any, Dict, KeysView, List, Tuple
import multiprocessing as multi
from report import report
from reader import reader
from io import StringIO
from ui import ui
import traceback
import cProfile
import logging
import json
import sys

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
            self.run_collector_pipeline(self.ips)
        else:
            actual_ips = self.filter_record_ips(self.ips, record_ips)
            self.run_collector_pipeline(actual_ips.keys())

        logger.info("Recording ips")
        # merge dicts and record
        self.record_ips({**actual_ips, **record_ips})


#   ========================================================================
#                       Collector Process Stuff
#   ========================================================================

    def all_collectors(self) -> List[Collector]:
        '''
        Provide a list of collectors for each type
        '''
        col_list = []
        for col_type in Collector_Types:
            col_list.append(
                self.factory.of(col_type)
            )
        return col_list

    def process_pipe_data(
        self,
        pipe_pairs: List[Tuple[Connection, Connection]]
    ) -> None:
        '''
        Manages the processing of pipe received from the parent
        '''
        first = True
        for parent, child in pipe_pairs:
            multi.connection.wait([parent])
            data = parent.recv()
            self.parse_pipe_data(data, use_ip=first)
            first = False

    def pipes_and_processes(
        self,
        queues: List[multi.Queue]
    ) -> Tuple[List[Any], List[multi.Process]]:
        pipe_pairs = []
        processes = []
        for queue in queues:
            logger.info(f"Spining up collector process for: {queue}")
            parent, child = multi.Pipe()
            process = multi.Process(
                target=self.process_collector_tasks,
                args=(queue, child)
            )
            pipe_pairs.append((parent, child))
            processes.append(process)
        return pipe_pairs, processes

    def run_collector_pipeline(self, ips: KeysView[Any]) -> None:
        '''
        The `master` method for all collector
        pipes, processes, and tasks.
        '''
        # queue up all collector tasks
        logger.info("Building collector task queues")
        queues: List[multi.Queue] = []
        for collector in self.collectors:
            queues.append(
                self.add_ip_tasks(multi.Queue(), ips, collector)
            )

        # initalize pip pairs and processes for each task-queue
        pipe_pairs, processes = self.pipes_and_processes(queues)

        # spin up processes
        for process in processes:
            logger.info(f"Spinning up process: {process}")
            process.start()

        for ip in ips:
            self.process_pipe_data(pipe_pairs)

        # join and close
        for process in processes:
            logger.info(f"Closing process: {process}")
            process.join()
            process.close()

        for parent, child in pipe_pairs:
            logger.info(f"Closing pipe: {parent}")
            parent.close()


    def parse_pipe_data(self, data: List[str], use_ip: bool=False) -> None:
        '''
        Takes in data from a piped collector result.
        Will attmpt to parse that data and send it to the appropriate modules.
        i.e. ui, report etc.

        Params:
            data - the data to parse
            use_ip - whether or not the parsed version
                     should include the ip address
        Time:
            constant
        Space:
            linear with the size of the collector data input
        '''
        ip = data[0]
        header = data[1]
        report = StringIO()
        if use_ip:
            self.ui.display(header, ip)
            report.write(f"/*\n\t{ip}\n*/\n")
        else:
            self.ui.display(header)
        report.write(f"/*\n{header}\n*/\n")
        report.write(data[2])

        self.report.write_report(report.getvalue())

    def process_collector_tasks(
        self,
        queue: multi.Queue,
        pipe: Connection
    ) -> None:
        '''
        Attempts to process the task queue.
        Will send the results through the pipe as needed.

        Params:
            queue - the queue of tasks to process
            pipe - where to send the resutls through
        Time:
            Constant
        Space:
            Constant
        '''
        while not queue.empty():
            task = queue.get()
            ip = task[0]
            collector = task[1]
            collector.ip = ip
            header = collector.header()
            report = collector.report()
            logger.info(f"Header and report received")
            logger.info(f"Done processing {task}")
            pipe.send([ip, header, report])

    def add_ip_tasks(
        self,
        queue: multi.Queue,
        ips: KeysView[Any],
        collector: Collector
    ) -> multi.Queue:
        '''
        Adds a set of ip and collector to the queue
        for each ip in the global list of ips

        Params:
            queue - the queue to add elements
            ips - the list of ip address to queue up for
            collector - the collectors.Collector to use
        Time:
            linear with the number of ips
        '''
        for ip in ips:
            queue.put([ip, collector])
        return queue


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

if __name__ == "__main__":
    #cProfile.run("IP_Checker().main()")
    IP_Checker().main()
