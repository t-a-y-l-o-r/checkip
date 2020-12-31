from typing import Any
import os

#   ========================================================================
#                       Table of Contents
#   ========================================================================
# 1. Environ
#
#
#
#
#
#   ========================================================================
#                       Description
#   ========================================================================
# This module handles any common utility stuff
#
#

def environ_or_default(environ: str, default: Any) -> Any:
    try:
        return os.environ[environ]
    except:
        return default
