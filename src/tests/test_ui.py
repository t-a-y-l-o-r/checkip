from typing import Dict, Any
from pathlib import Path
from ui import ui
import socket
import pytest

#   ========================================================================
#                       Table of Contents
#   ========================================================================
# 1. Globals
# 2. Fixtures
# 3. Object Construction
# 4. IP
# 5. File reading
#
#
#
#   ========================================================================
#                       Description
#   ========================================================================
#  This modules handles the tests for the `ui` module
#

#   ========================================================================
#                       Globals
#   ========================================================================

UI_EXPECTED_ARGS = {
    "ip",
    "input_file",
    "host",
    "force",
    "silent",
    "verbose"
}

TEST_IP_FILE = "test_ip.txt"
DEFAULT_DIR = "./tmp"


#   ========================================================================
#                       Fixtures
#   ========================================================================

@pytest.fixture(scope="session")
def ip_file(tmpdir_factory) -> Path:
    '''
    Generates the temporary ip file
    '''
    tmp_file = tmpdir_factory.mktemp(DEFAULT_DIR).join(TEST_IP_FILE)
    tmp_file.write("8.8.8.8")
    return tmp_file

#   ========================================================================
#                       Object Construction
#   ========================================================================

def test_argument_setup() -> None:
    """
    Ensures the ui.UI class constructs the correct arguments
    """
    conf = ui.UI_Config(
        testing=True,
        args=[
        "-ip",
        "0.0.0.0"
        ]
    )
    ui_obj = ui.UI(config=conf)
    args = set(ui_obj.args.keys())
    message = "".join([
        f"EXPECTED: {UI_EXPECTED_ARGS} does not match ",
        f"ACTUAL: {args} for UI(): {ui_obj}"
    ])
    assert UI_EXPECTED_ARGS == args, message

#   ========================================================================
#                       IP/Host Argument
#   ========================================================================


def test_ip_already_set() -> None:
    '''
    Tests the base case for the ip property
    Ensuring the inner value is always provided when set
    '''
    conf = ui.UI_Config(
        testing=True,
        args=[
        "-ip",
        "0.0.0.0"
        ]
    )
    ui_obj = ui.UI(config=conf)
    ip_list = [
        "0.0.0.0",
        "1.1.1.1",
        "8.8.8.8",
        "127.0.0.1"
    ]
    for ip in ip_list:
        ui_obj._ip = ip
        message = "".join([
            f"EXPECTED: {ip} does not match ",
            f"ACTUAL: {ui_obj.ip} for UI(): {ui_obj}"
        ])
        assert ui_obj.ip == ip, message


def test_ip_raw_ip() -> None:
    '''
    Ensures that a raw ip address from the `user` is
    identical to the stored proptery
    '''
    ip_list = [
        "0.0.0.0",
        "1.1.1.1",
        "8.8.8.8",
        "127.0.0.1"
    ]
    for ip in ip_list:
        conf = ui.UI_Config(
            testing=True,
            args=[
            "-ip",
            ip
            ]
        )
        ui_obj = ui.UI(config=conf)
        message = "".join([
            f"EXPECTED: {ip} does not match ",
            f"ACTUAL: {ui_obj.ip} for UI(): {ui_obj}"
        ])
        assert ui_obj.ip == ip, message

def test_ip_from_host() -> None:
    '''
    Ensures the ip property is identical to the
    ip resolved for a user input url
    '''
    host_list = [
        "google.com",
        "nmap.com",
        "github.com",
        "gitlab.com"
    ]
    for host in host_list:
        conf = ui.UI_Config(
            testing=True,
            args=[
            "--host",
            host
            ]
        )
        ip = socket.gethostbyname(host)
        ui_obj = ui.UI(config=conf)
        message = "".join([
            f"EXPECTED: {ip} does not match ",
            f"ACTUAL: {ui_obj.ip} for UI(): {ui_obj}"
        ])
        assert ui_obj.ip == ip, message

def test_ip_from_host_failure() -> None:
    '''
    Ensures the ip property throws and error
    '''
    host_list = [
        "google///.com",
        "nmap.comasdasldjnhasd",
        "asdhajlsdnljsagithub.com",
        "htttp://gitlab.com.com.com.com"
    ]
    for host in host_list:
        conf = ui.UI_Config(
            testing=True,
            args=[
            "--host",
            host
            ]
        )
        ui_obj = ui.UI(config=conf)
        with pytest.raises(ValueError):
            ip = ui_obj.ip

def test_ip_validation() -> None:
    '''
    Ensures ip validation works for valid ip addresses
    '''
    ip_list = [
        "0.0.0.0",
        "1.1.1.1",
        "8.8.8.8",
        "127.0.0.1"
    ]
    for ip in ip_list:
        conf = ui.UI_Config(
            testing=True,
            args=[
            "-ip",
            ip
            ]
        )
        ui_obj = ui.UI(config=conf)
        expected = True
        actual = ui_obj._validate_ip(ip)
        message = "".join([
            f"EXPECTED: {expected} does not match ",
            f"ACTUAL: {actual} for UI(): {ui_obj}"
        ])
        assert expected == actual, message

def test_ip_validation_failure() -> None:
    '''
    Ensures ip validation fails for invalid ip addresses
    '''
    ip_list = [
        "aavs.0.0.0",
        "lashdlasd",
        None,
        123
    ]
    for ip in ip_list:
        conf = ui.UI_Config(
            testing=True,
            args=[
            "-ip",
            ip
            ]
        )
        ui_obj = ui.UI(config=conf)
        expected = False
        actual = ui_obj._validate_ip(str(ip))
        message = "".join([
            f"EXPECTED: {expected} does not match ",
            f"ACTUAL: {actual} for UI(): {ui_obj}"
        ])
        assert expected == actual, message

#   ========================================================================
#                       File Argument
#   ========================================================================

def test_ip_file_set(ip_file) -> None:
    '''
    Ensures that the correct arument value is returned when
    the inner argument is already set
    '''
    file_str = str(ip_file)
    conf = ui.UI_Config(
        testing=True,
        args=[
            "-ip",
            "8.8.8.8"
        ]
    )
    ui_obj = ui.UI(config=conf)
    ui_obj._ip_file = file_str
    actual = ui_obj.ip_file
    expected = file_str
    message = "".join([
        f"EXPECTED: {expected} does not match ",
        f"ACTUAL: {actual} for UI(): {ui_obj}"
    ])
    assert expected == actual, message

def test_ip_file_no_file() -> None:
    '''
    Ensures that the correct arument value is returned when
    the inner argument is empty
    '''
    conf = ui.UI_Config(
        testing=True,
        args=[
            "-ip",
            "8.8.8.8"
        ]
    )
    ui_obj = ui.UI(config=conf)
    actual = ui_obj.ip_file
    expected = None
    message = "".join([
        f"EXPECTED: {expected} does not match ",
        f"ACTUAL: {actual} for UI(): {ui_obj}"
    ])
    assert expected == actual, message

def test_ip_file_has_file(ip_file) -> None:
    '''
    Ensures that the correct arument value is returned when
    the file is provided properly
    '''
    file_str = str(ip_file)
    conf = ui.UI_Config(
        testing=True,
        args=[
            "--input-file",
            str(file_str)
        ]
    )
    ui_obj = ui.UI(config=conf)

    actual = ui_obj.ip_file
    expected = file_str
    message = "".join([
        f"EXPECTED: {expected} does not match ",
        f"ACTUAL: {actual} for UI(): {ui_obj}"
    ])
    assert expected == actual, message

def test_ip_file_invalid_file() -> None:
    '''
    Ensures that the correct arument value is returned when
    the file is invalid
    '''
    conf = ui.UI_Config(
        testing=True,
        args=[
            "--input-file",
            "hasldjhalsjdn"
        ]
    )
    ui_obj = ui.UI(config=conf)

    actual = ui_obj.ip_file
    expected = None
    message = "".join([
        f"EXPECTED: {expected} does not match ",
        f"ACTUAL: {actual} for UI(): {ui_obj}"
    ])
    assert expected == actual, message

#   ========================================================================
#                       UI ARGS
#   ========================================================================

def test_ui_args_unique() -> None:
    '''
    Ensures that all values for UI_Args is unique
    '''
    count_of_args: Dict[Any, int] = {}
    for arg in ui.UI_Args:
        message = "".join([
            f"WARNING: {arg} was found in UI_Args more than once"
        ])
        assert arg not in count_of_args, message
        count_of_args.setdefault(arg, 1)

def test_ui_args_match_ui_args() -> None:
    '''
    Ensures that the UI_Args always exist within UI.args
    '''
    conf = ui.UI_Config(
        testing=True,
        args=[
            "-ip",
            "8.8.8.8"
        ]
    )
    ui_obj = ui.UI(conf)

    enum_args: Dict[Any, int] = {}
    for arg in ui.UI_Args:
        value = arg.value
        enum_args[value] = enum_args.setdefault(value, 0) + 1

    obj_args: Dict[Any, int] = {}
    for arg in ui_obj.args:
        obj_args[arg] = obj_args.setdefault(arg, 0) + 1

    message = "".join([
        f"EXPECTED: {enum_args} does not match ",
        f"ACTUAL: {obj_args} for UI(): {ui_obj}"
    ])
    assert enum_args == obj_args, message

#   ========================================================================
#                       Force
#   ========================================================================

def test_force_manual() -> None:
    '''
    Ensures that all branches of the ui.force
    execute as expeted.
    Providing any existing value if there is one
    '''
    conf = ui.UI_Config(
        testing=True,
        args=[
            "-ip",
            "8.8.8.8"
        ]
    )
    ui_obj = ui.UI(conf)
    us_obj._force = True

    actual = us_obj.force
    expected = True

    message = "".join([
        f"EXPECTED: {expected} does not match ",
        f"ACTUAL: {actual} for UI(): {ui_obj}"
    ])
    assert expected == actual, message

    us_obj._force = False

    actual = us_obj.force
    expected = False

    message = "".join([
        f"EXPECTED: {expected} does not match ",
        f"ACTUAL: {actual} for UI(): {ui_obj}"
    ])
    assert expected == actual, message

def test_force_args() -> None:
    '''
    Ensures that all branches of the ui.force
    execute as expeted.
    Providing any existing value if there is one
    '''
    conf = ui.UI_Config(
        testing=True,
        args=[
            "-ip",
            "8.8.8.8"
            "--force"
        ]
    )
    ui_obj = ui.UI(conf)

    actual = us_obj.force
    expected = True

    message = "".join([
        f"EXPECTED: {expected} does not match ",
        f"ACTUAL: {actual} for UI(): {ui_obj}"
    ])
    assert expected == actual, message

    conf = ui.UI_Config(
        testing=True,
        args=[
            "-ip",
            "8.8.8.8"
        ]
    )
    ui_obj = ui.UI(conf)

    actual = us_obj.force
    expected = False

    message = "".join([
        f"EXPECTED: {expected} does not match ",
        f"ACTUAL: {actual} for UI(): {ui_obj}"
    ])
    assert expected == actual, message
