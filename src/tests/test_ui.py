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

@pytest.fixture
def ip_file(tmp_path):
    '''
    Generates the temporary ip file
    '''
    tmp_file = tmpdir.mkdir(DEFAULT_DIR).join(TEST_IP_FILE)
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
            print(f"host: {host}")
            ip = ui_obj.ip
            print("error did not happen")

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
        actual = ui_obj._validate_ip(ip)
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
    conf = ui.UI_Config(
        testing=True,
        args=[
            "-ip",
            "8.8.8.8"
        ]
    )
    ui_obj = ui.UI(config=conf)
    ui_obj._ip_file = ip_file
    actual = ui_obj.ip_file
    expected = ip_file
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
    conf = ui.UI_Config(
        testing=True,
        args=[
            "--input-file",
            ip_file
        ]
    )
    ui_obj = ui.UI(config=conf)

    actual = ui_obj.ip_file
    expected = ip_file
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
