from io import StringIO
from typing import Dict, Any, Optional, List
import argparse
import logging
import socket
import json
import sys
import os
import re
#   ========================================================================
#                       Table of Contents
#   ========================================================================
# 1. Globals
# 2. UI_Config - Class
# 3. UI - Class
#
#
#
#   ========================================================================
#                       Description
#   ========================================================================
# This module is the "user interface" of the program.
#
# It primarily handles and parses the argument input from the user.
#

#   ========================================================================
#                       Globals
#   ========================================================================

RED = "\033[91m"
YELLOW = "\033[93m"
CLEAR = "\033[0m"


logging.basicConfig(
    filename=".log",
    filemode="w",
    format="%(name)s - %(levelname)s - %(message)s",
    level=logging.DEBUG
)
logger = logging.getLogger("ipchecker-ui")

#   ========================================================================
#                       UI_Config - Class
#   ========================================================================

class UI_Config():
    def __init__(self, testing=False, args=None):
        self.testing = testing
        self._args: Optional[List[str]] = args

    @property
    def args(self) -> Optional[List[str]]:
        '''
        Provides arguments to be ingested by the ui engine, if they exist
        '''
        return self._args


#   ========================================================================
#                       UI - Class
#   ========================================================================

class UI():
    def __init__(self, config=UI_Config()) -> None:
        self._config = config
        self._ip: Optional[Any] = None
        self._ip_file: Optional[str] = None
        self._all_ips: Optional[bool] = None
        self.silent = False

        self._parser = argparse.ArgumentParser(
            description="Checks the given ip(s) for security concerns"
        )
        self._args: Optional[Dict[Any, Any]] = None

        self._parser.add_argument(
            "-ip",
            action="store",
            metavar="--ip",
            type=str,
            help="".join([
                "The ip to check for security concerns. ",
                "Required if `-if` is not set"
            ])
        )
        self._parser.add_argument(
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
        self._parser.add_argument(
            "-u",
            "--host",
            action="store",
            metavar="--host",
            type=str,
            help="".join([
                "The host to check for security concners.",
                "Required if no ip is provided"
            ])
        )
        self._parser.add_argument(
            "-f",
            "--force",
            action="store_true",
            help="".join([
                "Ignores the unique ip filtering. Ensuring",
                "all given ips will be scanned"
            ])
        )
        self._parser.add_argument(
            "-s",
            "--silent",
            action="store_true",
            help="Will stop all stdIO from printing."
        )
        self._parser.add_argument(
            "-v",
            "--verbose",
            action="store_true",
            help="".join([
                "Ensures additional information is output"
            ])
        )

    @property
    def args(self) -> Dict[Any, Any]:
        '''
        Decides how to get the user provided arguments from the inital run.

        Will provide the arguments as a dict of {flag: value} pairs
        '''
        if self._args:
            return self._args
        else:
            # system provided configuration arguments take precedent
            if self._config.args:
                self._args = vars(self._parser.parse_args(
                    self._config.args
                ))
            else:
                # otherwise accept the user flags
                self._args = vars(self._parser.parse_args())
            return self._args

    @property
    def ip(self) -> Optional[str]:
        if self._ip:
            return self._ip
        else:
            keys = self.args.keys()
            has_raw_ip = "ip" in keys and self.args["ip"]
            has_host = "host" in keys and self.args["host"]

            if has_raw_ip:
                self._ip = self.args["ip"]
            elif has_host:
                try:
                    self._ip = socket.gethostbyname(self.args["host"])
                except socket.gaierror as e:
                    print(f"[*] Unable to resolve host name: {self.args['host']}")
                    logger.warning(e)
            self._validate_ip(self._ip)
            return self._ip

    @property
    def ip_file(self) -> Optional[str]:
        if self._ip_file:
            return self._ip_file
        else:
            keys = self.args.keys()
            has_file = "input_file" in keys and self.args["input_file"]
            if has_file:
                self._ip_file = self.args["input_file"]
                self._validate_ip_file(self._ip_file)
            return self._ip_file

    @property
    def all_ips(self) -> bool:
        if self._all_ips is not None:
            return self._all_ips
        else:
            keys = self.args.keys()
            self._all_ips = "force" in keys
            return self._all_ips

    def _validate_ip(self, ip: Optional[str]) -> None:
        '''
        Validates the ip against a pattern

        IPV4. ###.###.###.###
        '''
        passed = True
        if not ip:
            passed = False
        elif not re.compile("(\\d+\\.){3}(\\d+)").match(ip):
           passed = False

        if not passed:
            if not self.silent:
                logger.debug(f"Invalid ipv4 address: {ip}")
                print("".join([
                    f"{RED}[*] Warning:{CLEAR} ",
                    f"{ip} is an invalid ipv4 address"
                ]))
            if not self._config.testing:
                sys.exit(1)

    def _validate_ip_file(self, file_path: Optional[str]) -> None:
        '''
        Attempts to validat the given file path
        '''
        passed = True
        if not file_path:
            passed = False
        elif not os.path.isfile(file_path):
            passed = False

        if not passed:
            if not self.silent:
                logger.debug(f"Invalid file: {file_path}")
                print("".join([
                    f"{RED}[*] Warning:{CLEAR} ",
                    f"{file_path} is not a valid file!"
                ]))
            if not self._config.testing:
                sys.exit(1)

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
