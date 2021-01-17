from typing import Dict, Any, Optional, List
from io import StringIO
from enum import Enum
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
#                       Args - Enum
#   ========================================================================

class UI_Args(Enum):
    IP = "ip"
    IP_FILE = "input_file"
    HOST = "host"
    FORCE = "force"
    SILENT = "silent"
    VERBOSE = "verbose"


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
        '''
        Provides the given ipv4 address. Priority is as follows:

        1. An ipv4 value provided by the `-ip` flag
        2. A resolved host ip address per the `--host` flag
        '''
        if self._ip:
            return self._ip
        else:
            keys = self.args.keys()
            ip_flag = UI_Args.IP.value
            host_flag = UI_Args.HOST.value
            has_raw_ip = ip_flag in keys and self.args[ip_flag]
            has_host = host_flag in keys and self.args[host_flag]

            if has_raw_ip:
                self._ip = self.args[ip_flag]
            elif has_host:
                try:
                    self._ip = socket.gethostbyname(self.args[host_flag])
                except socket.gaierror as e:
                    logger.warning(e)
                    raise ValueError(
                        f"[*] Unable to resolve host name: {self.args[host_flag]}"
                    )
            else: # nothing detected, return None
                self._ip = None
                return self._ip
            passed = self._validate_ip(self._ip)
            if not passed: # exit on bad ip
                self._bad_ip_exit(self._ip)
            return self._ip

    def _bad_ip_exit(self, ip) -> None:
        if not self.silent:
            logger.debug(f"Invalid ipv4 address: {ip}")
            print("".join([
                f"{RED}[*] Warning:{CLEAR} ",
                f"{ip} is an invalid ipv4 address"
            ]))
        if not self._config.testing:
            sys.exit(1)

    @property
    def ip_file(self) -> Optional[str]:
        '''
        Provides access to the file name for the list of ips
        '''
        if self._ip_file:
            return self._ip_file
        else:
            keys = self.args.keys()
            file_flag = UI_Args.IP_FILE.value
            has_file = file_flag in keys and self.args[file_flag]
            if has_file:
                self._ip_file = self.args[file_flag]
                self._validate_ip_file(self._ip_file)
            else: # no file provided
                self._ip_file = None
            return self._ip_file

    @property
    def all_ips(self) -> bool:
        if self._all_ips is not None:
            return self._all_ips
        else:
            keys = self.args.keys()
            self._all_ips = "force" in keys
            return self._all_ips

    def _validate_ip(self, ip: Optional[str]) -> bool:
        '''
        Validates the ip against a pattern

        IPV4. ###.###.###.###
        '''
        if not ip:
            return False
        elif not re.compile("(\\d+\\.){3}(\\d+)").match(str(ip)):
            return False
        else:
            return True


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

    def display_help(self) -> None:
        '''
        Displays the usage message for the cli
        '''
        self._parser.print_help()
