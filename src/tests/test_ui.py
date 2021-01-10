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


def
