from typing import Dict, Any
from pathlib import Path
from ui import ui
import socket
import pytest
import sys

#   ========================================================================
#                       Table of Contents
#   ========================================================================
# 1. Globals
# 2. Fixtures
# 3. Object Construction
# 4. IP
# 5. File reading
# 6. UI ARGS
# 7. Force
# 8. Validate IP
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
    ui_obj._force = True

    actual = ui_obj.force
    expected = True

    message = "".join([
        f"EXPECTED: {expected} does not match ",
        f"ACTUAL: {actual} for UI(): {ui_obj}"
    ])
    assert expected == actual, message

    ui_obj._force = False

    actual = ui_obj.force
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
    Given the value is NOT already in memory and must be calculated
    '''
    conf = ui.UI_Config(
        testing=True,
        args=[
            "-ip",
            "8.8.8.8",
            "--force"
        ]
    )
    ui_obj = ui.UI(conf)

    actual = ui_obj.force
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

    actual = ui_obj.force
    expected = False

    message = "".join([
        f"EXPECTED: {expected} does not match ",
        f"ACTUAL: {actual} for UI(): {ui_obj}"
    ])
    assert expected == actual, message

#   ========================================================================
#                       Validate IP
#   ========================================================================

def test_validate_ip_empty() -> None:
    '''
    Ensures that the ui._validate_ip()
    call returns `False` when a falsey value is provided
    '''
    conf = ui.UI_Config(
        testing=True,
        args=[
            "-ip",
            "8.8.8.8",
            "--force"
        ]
    )
    ui_obj = ui.UI(conf)

    falsey_values = [
        "",
        None
    ]
    expected = False
    for value in falsey_values:
        actual = ui_obj._validate_ip(value)
        message = "".join([
            f"EXPECTED: {expected} does not match ",
            f"ACTUAL: {actual} for UI(): {ui_obj}"
        ])
        assert expected == actual, message

def test_validate_ip_no_match() -> None:
    '''
    Ensures that the ui._validate_ip()
    call returns `False` when a a bad pattern is provided
    '''
    conf = ui.UI_Config(
        testing=True,
        args=[
            "-ip",
            "8.8.8.8",
            "--force"
        ]
    )
    ui_obj = ui.UI(conf)

    bad_values = [
        "8.0",
        "abc",
        "-1,000"
    ]
    expected = False
    for value in bad_values:
        actual = ui_obj._validate_ip(value)
        message = "".join([
            f"EXPECTED: {expected} does not match ",
            f"ACTUAL: {actual} for UI(): {ui_obj}"
        ])
        assert expected == actual, message

def test_validate_ip_passes() -> None:
    '''
    Ensures that the ui._validate_ip()
    call returns `True` when a a good pattern is provided
    '''
    conf = ui.UI_Config(
        testing=True,
        args=[
            "-ip",
            "8.8.8.8",
            "--force"
        ]
    )
    ui_obj = ui.UI(conf)

    bad_values = [
        "8.8.8.8",
        "127.0.0.1",
        "192.168.0.1"
    ]
    expected = True
    for value in bad_values:
        actual = ui_obj._validate_ip(value)
        message = "".join([
            f"EXPECTED: {expected} does not match ",
            f"ACTUAL: {actual} for UI(): {ui_obj}"
        ])
        assert expected == actual, message

#   ========================================================================
#                       Args
#   ========================================================================

def test_args_already_set() -> None:
    '''
    Ensures that the arugments provided are
    the values stored when already in memory
    '''
    conf = ui.UI_Config(
        testing=True,
        args=[
            "-ip",
            "8.8.8.8"
        ]
    )
    ui_obj = ui.UI(conf)
    args = {
        "ip": "1.1.1.1",
        "input_file": None,
        "host": None,
        "force": False,
        "silent": False,
        "verbose": False

    }
    ui_obj._args = args
    actual = ui_obj.args
    message = "".join([
        f"EXPECTED: {args} does not match ",
        f"ACTUAL: {actual} for UI(): {ui_obj}"
    ])
    assert args == actual, message

def test_args_from_config() -> None:
    '''
    Ensures that the arugments provided are
    the same as the config object passed in
    '''
    conf = ui.UI_Config(
        testing=True,
        args=[
            "-ip",
            "8.8.8.8"
        ]
    )
    ui_obj = ui.UI(conf)
    args = {
        "ip": "8.8.8.8",
        "input_file": None,
        "host": None,
        "force": False,
        "silent": False,
        "verbose": False

    }
    actual = ui_obj.args
    message = "".join([
        f"EXPECTED: {args} does not match ",
        f"ACTUAL: {actual} for UI(): {ui_obj}"
    ])
    assert args == actual, message


def test_args_from_user_input() -> None:
    '''
    Ensures that the arugments provided are
    the same as the config object passed in
    '''
    '''
    print(sys.argv)
    sys.argv.append(
        "-ip "
    )
    sys.argv.append("8.8.8.8")
    print(sys.argv)
    '''
    root = "./src/checkip.py"
    argument_list = [
        {
            "args": [
                root,
                "-ip",
                "8.8.8.8"
            ],
            "expected": {
                "ip": "8.8.8.8",
                "input_file": None,
                "host": None,
                "force": False,
                "silent": False,
                "verbose": False
            }
        },
        {
            "args": [
                root,
                "-ip",
                "1.1.1.1"
            ],
            "expected": {
                "ip": "1.1.1.1",
                "input_file": None,
                "host": None,
                "force": False,
                "silent": False,
                "verbose": False
            }
        },
        {
            "args": [
                root,
                "-u",
                "google.com"
            ],
            "expected": {
                "ip": None,
                "input_file": None,
                "host": "google.com",
                "force": False,
                "silent": False,
                "verbose": False
            }
        },
    ]

    for arg_set in argument_list:
        arguments = arg_set["args"]
        expected = arg_set["expected"]
        sys.argv = list(arguments)

        conf = ui.UI_Config(
            testing=True,
            args=None
        )
        ui_obj = ui.UI(conf)
        actual = ui_obj.args

        message = "".join([
            f"EXPECTED: {expected} does not match ",
            f"ACTUAL: {actual} for UI(): {ui_obj}"
        ])
        assert expected == actual, message
