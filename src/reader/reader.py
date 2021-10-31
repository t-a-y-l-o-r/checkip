from abc import (ABC, abstractmethod)
from typing import List, Dict
import json
import os
'''
Handles reading in ip addresses
from a file.

Will provde a list, map, or set of
those ips
'''

class Abstract_Reader(ABC):
    '''
    Defines the interface for the reader class.
    Determines how the reader should be interacted
    with by the controller class
    '''
    @abstractmethod
    def read_input_file(self, file_path: str) -> List[str]:
        pass

    @abstractmethod
    def read_record(self, file_path: str) -> Dict[str, str]:
        pass


class Reader(Abstract_Reader):
    '''
    Implements the Abstract_Reader class.
    '''
    def __init__(self):
        self._reader = None

    def read_input_file(self, file_path: str) -> List[str]:
        '''
        Implements the read_ips() function as defined
        in the Abstract_Reader() class.
        Args:
            file_path - the path to the ips file
        Returns:
            a collecttion of the ips
        Time:
            Linear with regard to the file size
        Space:
            Linear with regard to the # of ips
        '''
        ip_list = list()
        with open(file_path, "r") as f:
           ips = f.read().split("\n")
           for ip in ips:
                if ip != "":
                    ip_list.append(ip)
        return ip_list

    def read_record(self, file_path: str) -> Dict[str, str]:
        '''
        Implements the read_record function as defined
        in the Abstract_Reader() class.

        Args:
            file_path - the path to the record file
        Returns:
            A map of the data found
        time:
            linear with the size of the file
        Space:
            linear with the size of the file
        '''
        if not os.path.exists(file_path):
            return dict()
        with open(file_path, "r") as f:
            ips = f.read()
            if not ips:
                return dict()
            return json.loads(ips)
