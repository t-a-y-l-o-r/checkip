#!/usr/bin/env python3
from collectors import collectors
from report import report
from reader import reader
from io import StringIO
import multi.as multi
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


PROCESSES = 1
logging.basicConfig(
    filename=".log",
    filemode="w",
    format="%(name)s - %(levelname)s - %(message)s",
    level=logging.DEBUG)
logger = logging.getLogger("ipchecker")

class IP_Checker():
    def __init__(self):
        self.ui = ui.UI()
        self.report = report.Report_Builder()
        self.factory = collectors.Collector_Factory()
        self.reader = reader.Reader()
        self.ips = list()
        logger.info("IP_Checker finished init")

#   ========================================================================
#                       Main Stuff
#   ========================================================================

    def main(self):
        '''
        The main function. Manages all of the sub-modules,
        and the ordering in which they will execute.
        Will attempt to validate that all necessary setup
        has completed.
        '''
        self.ui.args()
        if self.ui.ip is not None:
            self.ips.append(self.ui.ip)
        elif self.ui.input_file is not None:
            self.ips = self.reader.read_input_file(self.ui.input_file)
        else:
            logger.warning("No -if or -ip flag given")
            self.ui.parser.print_help()
            sys.exit(1)

        # ensure report is empty
        self.report.create_report()
        # check to see if a record exists, else create it
        record_ips = self.reader.read_record("./record.json")
        if record_ips is {}:
            self.report.create_record()

        # check if forcing all ips or not
        actual_ips = None
        if self.ui.all_ips:
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
#                       Collector Stuff
#   ========================================================================

    def run_collector_pipeline(self, ips):
        '''
        The `master` method for all collector
        pipes, processes, and tasks.
        '''
        # queue up all collector tasks
        logger.info("Building collector task queues")
        vt_queue = multi.Queue()
        otx_queue = multi.Queue()
        rob_queue = multi.Queue()
        vt_queue = self.add_vt_tasks(vt_queue, ips)
        otx_queue = self.add_otx_tasks(otx_queue, ips)
        rob_queue = self.add_rob_tasks(rob_queue, ips)

        logger.info("Spining up vt child-process")
        vt_main_pipe, vt_child_pipe = multi.Pipe()
        vt_process = multi.Process(
            target=self.process_collector_tasks,
            args=(vt_queue, vt_child_pipe)
        )
        logger.info("Spining up otx process")
        otx_main_pipe, otx_child_pipe = multi.Pipe()
        otx_process = multi.Process(
            target=self.process_collector_tasks,
            args=(otx_queue, otx_child_pipe)
        )
        logger.info("Spinning up robtex process")
        rob_main_pipe, rob_child_pipe = multi.Pipe()
        rob_process = multi.Process(
            target=self.process_collector_tasks,
            args=(
                rob_queue,
                rob_child_pipe
            )
        )
        logger.info("Processing vt tasts")
        vt_process.start()
        logger.info("Processing otx tasks")
        otx_process.start()
        logger.info("Processing robtext tasks")
        rob_process.start()

        for ip in ips:
            multi.connection.wait([vt_main_pipe])
            pipe_data = vt_main_pipe.recv()
            self.parse_pipe_data(pipe_data, use_ip=True)

            multi.connection.wait([otx_main_pipe])
            pipe_data = otx_main_pipe.recv()
            self.parse_pipe_data(pipe_data)

            multi.connection.wait([rob_main_pipe])
            pipe_data = rob_main_pipe.recv()
            self.parse_pipe_data(pipe_data)

        vt_process.join()
        vt_process.close()
        vt_main_pipe.close()
        logger.info("Vt tasks processed")

        otx_process.join()
        otx_process.close()
        otx_main_pipe.close()
        logger.info("OTX tasks processed")

        rob_process.join()
        rob_process.close()
        rob_main_pipe.close()
        logger.info("Robtex tasks processed")

    def parse_pipe_data(self, data, use_ip=False):
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

    def process_collector_tasks(self, queue, pipe):
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

    def add_vt_tasks(self, queue, ips):
        '''
        Adds a set of ip and collector to the queue
        for each ip in the global list of ips

        Params:
            queue - the queue to add elements
        Time:
            linear with the number of global ips
        Space:
            linear with the number of global ips
        '''
        collector = self.factory.create_virus_total_collector()
        for ip in ips:
            queue.put([ip, collector])
        return queue

    def add_otx_tasks(self, queue, ips):
        '''
        Adds a set of ip and collector to the queue
        for each ip in the global list of ips

        Params:
            queue - the queue to add elements
        Time:
            linear with the number of global ips
        Space:
            linear with the number of global ips
        '''
        collector = self.factory.create_otx_collector()
        for ip in ips:
            queue.put([ip, collector])
        return queue

    def add_rob_tasks(self, queue, ips):
        '''
        Adds a set of ip and collector to the queue
        for each ip in the global list of ips

        Params:
            queue - the queue to add elements
        Time:
            linear with the number of global ips
        Space:
            linear with the number of global ips
        '''
        collector = self.factory.create_robtex_collector()
        for ip in ips:
            queue.put([ip, collector])
        return queue

#   ========================================================================
#                       Record Stuff
#   ========================================================================

    def record_ips(self, ips):
        self.report.write_record(json.dumps(ips, indent=4,
                                            sort_keys=True))

    def filter_record_ips(self, given, record, display=True):
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
