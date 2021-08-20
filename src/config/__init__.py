from configparser import ConfigParser
from typing import Optional, Set
import utility
import os


#   ========================================================================
#                       Table of Contents
#   ========================================================================
# 1. Globals
# 2. Config, Class
# 3.
#
#
#
#
#
#   ========================================================================
#                       Description
#   ========================================================================
# This module handles the `config.ini` for the check-ip program.
#
# In general it handles the configration of the program.
# Which may include settings like API Keys, output settings, or other user
# related preferences.
#
#

#   ========================================================================
#                       Globals
#   ========================================================================

# general
KEY: str = "key"

# file stuff
CONFIG_ENVIRON: str = "CHECK_IP_CONFIG"
USER_DEF_CONFIG: Optional[str] = utility.environ_or_default(
    CONFIG_ENVIRON,
    None
)
HOME_FILE_PATH: str = "".join([
    os.environ["HOME"],
    "/.checkip",
    "/config.ini"
])
DEFAULT_CONFIG_LOCATION: str = "config.ini"

# vt
VIRUS_TOTAL_HEADER: str = "VIRUS_TOTAL"
VIRUS_TOTAL_KEYS: Set[str] = {
    KEY
}
VIRUS_TOTAL_ENVIRON: str = "VIRUS_TOTAL_KEY"
USER_DEF_VIRUS_TOTAL: Optional[str] = utility.environ_or_default(
    VIRUS_TOTAL_ENVIRON,
    None
)

# otx
OTX_HEADER: str = "OTX"
OTX_KEYS: Set[str] = {
    KEY
}
OTX_ENVIRON: str = "OTX_KEY"
USER_DEF_OTX: Optional[str] = utility.environ_or_default(
    OTX_ENVIRON,
    None
)



#   ========================================================================
#                       Config -- Class
#   ========================================================================


class Config():
    def __init__(self):
        self._config: Optional[ConfigParser] = None
        self._file: Optional[str] = None
        self._vt_key: Optional[str] = None
        self._otx_key: Optional[str] = None

    @property
    def config(self) -> ConfigParser:
        if self._config:
            return self._config
        else:
            self._config = ConfigParser()
            self._config.read(self.file_location)
            return self._config

    @property
    def file_location(self) -> str:
        '''
        Defines where the config file is located.
        Priority is as follows:
        1. User defined shell var
        2. Home Directory dot folder: `~/.checkip/config.ini`
        3. Local file: `local_dir/config.ini`
        '''
        if self._file:
            return self._file
        else:
            if os.path.exists(HOME_FILE_PATH):
                self._file = HOME_FILE_PATH
            else:
                self._file = DEFAULT_CONFIG_LOCATION
            return self._file

    @property
    def virus_total_key(self) -> str:
        '''
        Defines the virus_total api key
        Priority is as follows:
        1. Shell environ
        2. config.ini

        Will raise an error if it is not able to find a key
        '''
        return self._api_key(
            "_vt_key",
            USER_DEF_VIRUS_TOTAL,
            VIRUS_TOTAL_HEADER,
            "".join([
                "Checkip was not able to find ",
                "an appropriate api key for VIRUS TOTAL"
            ])
        )

    @property
    def otx_key(self) -> str:
        '''
        Defines the otx api key
        Priority:
        1. Shell environ
        2. config.ini
        '''
        return self._api_key(
            "_otx_key",
            USER_DEF_OTX,
            OTX_HEADER,
            "Checkip was not able to fin an appropriate api key for OTX"
        )

    def _api_key(
        self,
        inner_var: str,
        user_def: Optional[str],
        header: str,
        error_message: str) -> str:
        '''
        provides the value of a given api key, assuming it exists
        errors out otherwise
        '''
        attr = getattr(self, inner_var)
        if attr:
            return attr
        elif user_def:
            setattr(self, inner_var, user_def)
            return getattr(self, inner_var)
        else:
            api_key = self.config[header].get(KEY)
            if not api_key:
                raise KeyError(error_message)
            setattr(self, inner_var, api_key)
            return getattr(self, inner_var)
