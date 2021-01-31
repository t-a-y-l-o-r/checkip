from typing import Dict, Any
from pathlib import Path
from ui import ui
import socket
import pytest
import json
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
# 9. Args
# 10. Bad IP Exit
# 11. Silent
# 12. Bad File Exit
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

@pytest.fixture
def ui_obj() -> ui.UI:
    '''
    A simple ui test object
    '''
    conf = ui.UI_Config(
        testing=True,
        args=[
            "-ip",
            "8.8.8.8"
        ]
    )
    ui_obj = ui.UI(conf)
    return ui_obj

#   ========================================================================
#                       Object Construction
#   ========================================================================

def test_argument_setup(ui_obj) -> None:
    """
    Ensures the ui.UI class constructs the correct arguments
    """
    args = set(ui_obj.args.keys())
    message = "".join([
        f"EXPECTED: {UI_EXPECTED_ARGS} does not match ",
        f"ACTUAL: {args} for UI(): {ui_obj}"
    ])
    assert UI_EXPECTED_ARGS == args, message

#   ========================================================================
#                       IP/Host Argument
#   ========================================================================


def test_ip_already_set(ui_obj) -> None:
    '''
    Tests the base case for the ip property
    Ensuring the inner value is always provided when set
    '''
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

def test_ip_no_ip_no_host(ui_obj) -> None:
    '''
    Ensures that `None` is returned when there is no
    appropriate ip / host found
    '''
    expected = None
    ip_flag = ui.UI_Args.IP.value
    host_flag = ui.UI_Args.HOST.value

    # trick arg parser into validating the argument input
    # bit of a hack
    ui_obj.args
    ui_obj.args[ip_flag] = None
    ui_obj.args[host_flag] = None

    actual = ui_obj.ip
    message = "".join([
        f"EXPECTED: {expected} does not match ",
        f"ACTUAL: {actual} for UI(): {ui_obj}"
    ])
    assert expected == actual, message

def test_ip_bad_ip() -> None:
    bad_ip_patterns = [
        "google.com",
        "hello_world",
        "idk what lese",
        "-1"
    ]
    for pattern in bad_ip_patterns:
        conf = ui.UI_Config(
            testing=True,
            args=[
                "-ip",
                pattern
            ]
        )
        expected = None
        ui_obj = ui.UI(config=conf)

        actual = ui_obj.ip
        message = "".join([
            f"EXPECTED: {expected} does not match ",
            f"ACTUAL: {actual} for UI(): {ui_obj}"
        ])
        assert expected == actual, message


#   ========================================================================
#                       File Argument
#   ========================================================================

def test_ip_file_set(ui_obj, ip_file) -> None:
    '''
    Ensures that the correct arument value is returned when
    the inner argument is already set
    '''
    file_str = str(ip_file)
    ui_obj._ip_file = file_str
    actual = ui_obj.ip_file
    expected = file_str
    message = "".join([
        f"EXPECTED: {expected} does not match ",
        f"ACTUAL: {actual} for UI(): {ui_obj}"
    ])
    assert expected == actual, message

def test_ip_file_no_file(ui_obj) -> None:
    '''
    Ensures that the correct arument value is returned when
    the inner argument is empty
    '''
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

def test_ui_args_match_ui_args(ui_obj) -> None:
    '''
    Ensures that the UI_Args always exist within UI.args
    '''
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

def test_force_manual(ui_obj) -> None:
    '''
    Ensures that all branches of the ui.force
    execute as expeted.
    Providing any existing value if there is one
    '''
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

def test_args_already_set(ui_obj) -> None:
    '''
    Ensures that the arugments provided are
    the values stored when already in memory
    '''
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

def test_args_from_config(ui_obj) -> None:
    '''
    Ensures that the arugments provided are
    the same as the config object passed in
    '''
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

#   ========================================================================
#                       Bad IP Exit
#   ========================================================================

def test_bad_ip_exit_not_silent(capsys) -> None:
    '''
    Ensures appropriate input when silent is not passed
    '''
    ip = "google.com"
    conf = ui.UI_Config(
        testing=True,
        args=[
            "-ip",
            ip
        ]
    )
    ui_obj = ui.UI(conf)
    ui_obj._silent = False

    ui_obj._bad_ip_exit(ip)
    actual = capsys.readouterr().out

    expected = "".join([
        f"{ui.RED}[*] Warning:{ui.CLEAR} ",
        f"{ip} is an invalid ipv4 address\n"
    ])
    message = "".join([
        f"EXPECTED: {expected} does not match ",
        f"ACTUAL: {actual} for UI(): {ui_obj}"
    ])

    assert expected == actual, message

def test_bad_ip_exit_silent(capsys) -> None:
    '''
    Ensures appropriate input when silent is not passed
    '''
    ip = "google.com"
    conf = ui.UI_Config(
        testing=True,
        args=[
            "-ip",
            ip
        ]
    )
    ui_obj = ui.UI(conf)
    ui_obj._silent = True

    ui_obj._bad_ip_exit(ip)
    actual = capsys.readouterr().out

    expected = ""
    message = "".join([
        f"EXPECTED: {expected} does not match ",
        f"ACTUAL: {actual} for UI(): {ui_obj}"
    ])

    assert expected == actual, message

def test_bad_ip_exit_not_silent_not_testing() -> None:
    '''
    Ensures appropriate input when silent is not passed
    '''
    ip = "google.com"
    conf = ui.UI_Config(
        testing=False,
        args=[
            "-ip",
            ip
        ]
    )
    with pytest.raises(SystemExit):
        ui_obj = ui.UI(conf)
        ui_obj._silent = False

        ui_obj._bad_ip_exit(ip)

#   ========================================================================
#                       Silent
#   ========================================================================

def test_silent_set(ui_obj) -> None:
    '''
    Ensures that an already set `silent`
    value is properly provided
    '''
    silent_sets = [
        {
            "bool": True,
            "expected": True
        },
        {
            "bool": False,
            "expected": False

        }
    ]

    for pairs in silent_sets:
        set_to = pairs["bool"]
        expected = pairs["expected"]

        ui_obj._silent = set_to
        actual = ui_obj.silent

        message = "".join([
            f"EXPECTED: {expected} does not match ",
            f"ACTUAL: {actual} for UI(): {ui_obj}"
        ])
        assert expected == actual, message

def test_silent_not_set() -> None:
    '''
    Ensures that an already set `silent`
    value is properly provided
    '''
    silent_sets = [
        {
            "bool": True,
            "expected": True
        },
        {
            "bool": False,
            "expected": False

        }
    ]

    for pairs in silent_sets:
        silent = pairs["bool"]
        arg_list = [
            "-ip",
            "8.8.8.8"
        ]
        if silent:
            arg_list.append("--silent")
        conf = ui.UI_Config(
            testing=True,
            args=arg_list
        )
        ui_obj = ui.UI(conf)
        expected = pairs["expected"]

        actual = ui_obj.silent

        message = "".join([
            f"EXPECTED: {expected} does not match ",
            f"ACTUAL: {actual} for UI(): {ui_obj}"
        ])
        assert expected == actual, message

#   ========================================================================
#                       Bad File Exit
#   ========================================================================

def test_bad_file_exit_not_silent(capsys) -> None:
    '''
    Ensures appropriate input when silent is not set
    '''
    ip = "google.com"
    conf = ui.UI_Config(
        testing=True,
        args=[
            "--input-file",
            ip
        ]
    )
    ui_obj = ui.UI(conf)
    ui_obj._silent = False

    ui_obj._bad_file_exit(ip)
    actual = capsys.readouterr().out

    expected = "".join([
        f"{ui.RED}[*] Warning:{ui.CLEAR} ",
        f"{ip} is an invalid file\n"
    ])
    message = "".join([
        f"EXPECTED: {expected} does not match ",
        f"ACTUAL: {actual} for UI(): {ui_obj}"
    ])

    assert expected == actual, message

def test_bad_file_exit_silent(capsys) -> None:
    '''
    Ensures appropriate input when silent is set
    '''
    ip = "google.com"
    conf = ui.UI_Config(
        testing=True,
        args=[
            "--input-file",
            ip
        ]
    )
    ui_obj = ui.UI(conf)
    ui_obj._silent = True

    ui_obj._bad_file_exit(ip)
    actual = capsys.readouterr().out

    expected = ""
    message = "".join([
        f"EXPECTED: {expected} does not match ",
        f"ACTUAL: {actual} for UI(): {ui_obj}"
    ])

    assert expected == actual, message

def test_bad_file_exit_not_silent_not_testing() -> None:
    '''
    Ensures appropriate input when silent is not passed
    '''
    ip = "google.com"
    conf = ui.UI_Config(
        testing=False,
        args=[
            "--input-file",
            ip
        ]
    )
    with pytest.raises(SystemExit):
        ui_obj = ui.UI(conf)
        ui_obj._silent = False

        ui_obj._bad_file_exit(ip)

#   ========================================================================
#                       Validate IP File
#   ========================================================================

def test_valid_ip_file_empty(ui_obj, capsys) -> None:
    '''
    Ensures that `False` is returned when a no file is provided
    Also ensure the propery message is provided
    '''
    provided_file = None
    actual = ui_obj._valid_ip_file(provided_file)
    expected = False

    message = "".join([
        f"EXPECTED: {expected} does not match ",
        f"ACTUAL: {actual} for UI(): {ui_obj}"
    ])

    assert expected == actual, message

    # check print message
    actual = capsys.readouterr().out
    expected = "".join([
        f"{ui.RED}[*] Warning:{ui.CLEAR} ",
        f"{provided_file} is not a valid file!\n"
    ])
    assert expected == actual, message

def test_valid_ip_file_doesnt_exist(ui_obj, capsys) -> None:
    '''
    Ensures that `False` is returned when a none existent file is provided
    Also ensure the propery message is provided
    '''
    provided_file = "some_dumby_file.txt"
    actual = ui_obj._valid_ip_file(provided_file)
    expected = False

    message = "".join([
        f"EXPECTED: {expected} does not match ",
        f"ACTUAL: {actual} for UI(): {ui_obj}"
    ])

    assert expected == actual, message

    # check print message
    actual = capsys.readouterr().out
    expected = "".join([
        f"{ui.RED}[*] Warning:{ui.CLEAR} ",
        f"{provided_file} is not a valid file!\n"
    ])
    assert expected == actual, message

def test_valid_ip_file_does_exist(ui_obj, ip_file) -> None:
    '''
    Ensures that `True` is returned when a real file is provided
    '''
    actual = ui_obj._valid_ip_file(ip_file)
    expected = True

    message = "".join([
        f"EXPECTED: {expected} does not match ",
        f"ACTUAL: {actual} for UI(): {ui_obj}"
    ])

    assert expected == actual, message

#   ========================================================================
#                       Display
#   ========================================================================



def test_display_silent(ui_obj, capsys) -> None:
    '''
    Ensures that there is NO output when silent is set
    '''
    ui_obj._silent = True
    header = ""
    ui_obj.display(header)
    actual = capsys.readouterr().out
    expected = ""

    message = "".join([
        f"EXPECTED: {expected} does not match ",
        f"ACTUAL: {actual} for UI(): {ui_obj}"
    ])
    assert expected == actual, message

def test_display_no_silent(ui_obj, capsys) -> None:
    '''
    Ensures that the correct output is printed when silent is set
    '''
    ui_obj._silent = False

    header = ""
    ip = "8.8.8.8"
    ui_obj.display(header, ip=ip)
    actual = capsys.readouterr().out

    expected = "".join([
        "\n    =============================\n",
        f"     [ip]  {ip}  [ip]",
        "\n    =============================\n",
        f"{header}\n\n"
    ])

    message = "".join([
        f"EXPECTED: {repr(expected)} does not match ",
        f"ACTUAL: {repr(actual)} for UI(): {ui_obj}"
    ])
    assert expected == actual, message

def test_display_only_header(ui_obj, capsys) -> None:
    '''
    Ensures that ONLY the header is printed when ip is None
    '''
    ui_obj._silent = False

    header = ""
    ip = None
    ui_obj.display(header, ip=ip)
    actual = capsys.readouterr().out

    expected = f"{header}\n"

    message = "".join([
        f"EXPECTED: {repr(expected)} does not match ",
        f"ACTUAL: {repr(actual)} for UI(): {ui_obj}"
    ])

    assert expected == actual, message

#   ========================================================================
#                       Display Excluded IPs
#   ========================================================================

def test_display_excluded_ips_silent(ui_obj, capsys) -> None:
    '''
    Ensures that nothing is printed when silent
    '''
    ui_obj._silent = True

    ips = None
    ui_obj.display_excluded_ips(ips)

    actual = capsys.readouterr().out
    expected = ""

    message = "".join([
        f"EXPECTED: {repr(expected)} does not match ",
        f"ACTUAL: {repr(actual)} for UI(): {ui_obj}"
    ])

    assert expected == actual, message

def test_display_excluded_ips_not_silent(ui_obj, capsys) -> None:
    '''
    Ensures that the dict is printed when ips are provided
    '''
    ui_obj._silent = False

    notes = {"notes": "N/A"}

    ip_dict = {
        "8.8.8.8": notes,
        "1.1.1.1": notes,
        "2.2.2.2": notes
    }

    ui_obj.display_excluded_ips(ip_dict)

    actual = capsys.readouterr().out

    ip_json = json.dumps(ip_dict, indent=4, sort_keys=True)
    expected = "".join([
        f"[*]{ui.YELLOW} Notice: {ui.CLEAR} ",
        f"the following ips will NOT be scanned: {ip_json}\n"
    ])

    message = "".join([
        f"EXPECTED: {repr(expected)} does not match ",
        f"ACTUAL: {repr(actual)} for UI(): {ui_obj}"
    ])

    assert expected == actual, message
