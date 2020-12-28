from io import StringIO
from typing import Dict
import argparse
import logging
import json
import sys
import os
import re
'''
Author: Taylor Cochran
Since:
'''
RED = "\033[91m"
YELLOW = "\033[93m"
CLEAR = "\033[0m"


logging.basicConfig(filename=".log",
                    filemode="w",
                    format="%(name)s - %(levelname)s - %(message)s",
                    level=logging.DEBUG)
logger = logging.getLogger("ipchecker-ui")

class UI():
    def __init__(self) -> None:
        self.parser = argparse.ArgumentParser(
            description="Checks the given ip(s) for security concerns"
        )
        self.parser.add_argument(
            "-ap",
            "--all-ips",
            action="store_true",
            help="".join([
                "Ignores the unique ip filtering. Ensuring",
                "all given ips will be scanned"
            ])
        )
        self.parser.add_argument(
            "-s",
            "--silent",
            action="store_true",
            help="Will stop all stdIO from printing."
        )
        self.parser.add_argument(
            "-ip",
            action="store",
            metavar="--ip",
            type=str,
            help="".join([
                "The ip to check for security concerns. ",
                "Required if `-if` is not set"
            ])
        )
        self.parser.add_argument(
            "-if",
            "--input-file",
            action="store",
            metavar="--input-file",
            type=str,
            help="".join([
                "The input file containing newline ",
                "deliminated ip addresses. ",
                "Required if `-ip` is not set."
            ])
        )
        self.ip = None
        self.input_file = None
        self.all_ips = False
        self.silent = False

    def args(self) -> None:
        '''
        Attempts to parse the command line arguments
        provided to the main
        '''
        args = vars(self.parser.parse_args())
        logger.info(args)
        keys = args.keys()
        if "ip" in keys:
            self.ip = args["ip"]
        if "input_file" in keys:
            self.input_file = args["input_file"]
        if "input_file" in keys:
            input_fule = args["input_file"]
        self.all_ips = args["all_ips"]
        self.silent = args["silent"]

        if self.ip is not None:
            self.validate_ip(self.ip)
        elif self.input_file is not None:
            self.validate_input_file(self.input_file)

    def validate_ip(self, ip: str) -> None:
        '''
        Validates the ip against a pattern

        IPV4. ###.###.###.###
        '''
        if not re.compile("(\\d+\\.){3}(\\d+)").match(ip):
            if not self.silent:
                logger.debug(f"Invalid ipv4 address: {ip}")
                print("{0}[*] Warning:{1} `{2}` is an invalid ipv4 address".
                      format(RED, CLEAR, ip))
            sys.exit(1)

    def validate_input_file(self, file_path: str) -> None:
        '''
        Attempts to validat the given file path
        '''
        if not os.path.isfile(file_path):
            if not self.silent:
                logger.debug(f"Invalid file: {file_path}")
                print("{0}[*] Warning:{1} `{2}` is not a valid file!".
                      format(RED, CLEAR, file_path))

    def display(self, header: str, ip: str=None) -> None:
        '''
        Builds the command line version of the report from the given header
        '''
        if self.silent:
            return
        if ip is not None:
            ip_output = StringIO()
            ip_output.write("\n    =============================\n")
            ip_output.write(f"     [ip]  {ip}  [ip]")
            ip_output.write("\n    =============================\n")
            print(ip_output.getvalue())
        print(header)

    def display_excluded_ips(self, ips: Dict[str, str]) -> None:
        '''
        Will display the given set of ips
        which are NOT queued up to be scanned.
        '''
        logger.debug(f"Ignoring the following ips: {ips}")
        if self.silent:
            return
        ips_str = json.dumps(ips, indent=4, sort_keys=True)
        output = "".join([
            f"[*]{YELLOW} Notice: {CLEAR} ",
            f"the following ips will NOT be scanned: {ips_str}"
        ])
        print(output)
