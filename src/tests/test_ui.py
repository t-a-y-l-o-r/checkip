from ui import ui

#   ========================================================================
#                       Table of Contents
#   ========================================================================
# 1. Globals
# 2. Object Construction
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
UI_EXPECETED_ARGS = {
    "ip",
    "input_file",
    "host",
    "force",
    "silent",
    "verbose"
}

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
        f"EXPECTED: {UI_EXPECETED_ARGS} does not match ",
        f"ACTUAL: {args} for UI(): {ui_obj}"
    ])
    assert UI_EXPECETED_ARGS == args, message

#   ========================================================================
#                       IP Parsing
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
