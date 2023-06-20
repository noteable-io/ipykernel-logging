import json
import os
import re
import sys
import traceback
from typing import Optional

import structlog

# change this key to "message" if the processor goes after `rename_event_key`
MESSAGE_KEY = "event"


def redact_code_content(msg: str) -> str:
    """Removes the `code` value from execute_request content, which should
    a) help make the rest of the message more JSON-loadable, and
    b) prevent any PII or sensitive data from being logged.
    """
    # expect that 'code' can be found with a value that leads up to one of the
    # other valid execute_request keys
    valid_keys = [
        "allow_stdin",
        "silent",
        "store_history",
        "user_expressions",
        "user_variables",
    ]
    end_pattern = "|".join([f"'{key}'" for key in valid_keys])
    pattern = r"('code':\s)'.*?('" + end_pattern + ")"
    return re.sub(pattern, r"\1'<redacted>', \2", msg, flags=re.DOTALL)


def json_clean(msg: str) -> str:
    """Attempts to fix up the non-JSON-loadable log message.

    Example of a message we may see here, where json.loads() would break on things like `datetime`
    and `zmq.sugar.tracker.MessageTracker`:

    "{'header': {'msg_id': 'dbe276e7-80ea3d94bb8f9ca358e4a892_41', 'msg_type': 'execute_reply', 'username': 'username', 'session': 'dbe276e7-80ea3d94bb8f9ca358e4a892', 'date': datetime.datetime(2023, 6, 20, 14, 37, 19, 134395, tzinfo=datetime.timezone.utc), 'version': '5.3'}, 'msg_id': 'dbe276e7-80ea3d94bb8f9ca358e4a892_41', 'msg_type': 'execute_reply', 'parent_header': {'msg_id': '4315e4aa-694d-450a-bde3-06b95fa185e5', 'username': 'username', 'session': 'eed2507a-488c-4d42-eff4-7afa4b9f0a5b', 'msg_type': 'execute_request', 'version': '5.0', 'date': datetime.datetime(2023, 6, 20, 14, 37, 19, 123896, tzinfo=datetime.timezone.utc)}, 'content': {'status': 'ok', 'execution_count': 2, 'user_expressions': {}, 'payload': []}, 'metadata': {'started': datetime.datetime(2023, 6, 20, 14, 37, 19, 129938, tzinfo=datetime.timezone.utc), 'dependencies_met': True, 'engine': '5cd12473-da0f-4a2a-a9d6-21f2891016df', 'status': 'ok'}, 'tracker': <zmq.sugar.tracker.MessageTracker object at 0x7fc27b06b6d0>}"
    """
    msg = (
        msg.replace("True", "true")
        .replace("False", "false")
        .replace("None", "null")
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("'", '"')
    )

    if ": datetime." in msg:
        # 'date': datetime.datetime(2023, 6, 20, 14, 37, 19, 134395, tzinfo=datetime.timezone.utc)
        msg = (
            msg.replace(": datetime.", ': "datetime.')
            .replace("tzinfo=tzlocal()),", 'tzinfo=tzlocal())",')
            .replace("tzinfo=datetime.timezone.utc)", 'tzinfo=datetime.timezone.utc)"')
        )

    if ": <" in msg:
        # things like 'tracker': <zmq.sugar.tracker.MessageTracker object at 0x7fc27b06b6d0>
        msg = re.sub(r"(<.*?>)", r'"\1"', msg)

    return msg


def remove_ansi_from_text(text: str) -> str:
    """Removes ANSI escape sequences from text.
    Useful for cleaning colored text from formatted traceback strings.
    """
    pattern = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return pattern.sub("", text)


def parse_message(event_dict: dict, msg: str, msg_type: Optional[str] = None) -> dict:
    """Attempts to clean and parse the message into a dict and add it to the event_dict."""
    msg = remove_ansi_from_text(msg)
    msg = redact_code_content(msg)
    msg_json: str = json_clean(msg)
    try:
        msg_dict: dict = json.loads(msg_json)
    except Exception:  # noqa
        # something didn't parse correctly, don't raise anything since that could cause odd behavior
        return event_dict

    msg_type = msg_dict.get("header", {}).get("msg_type", msg_type)
    event_dict["msg_type"] = msg_type

    if "code" in msg_dict:
        # remove source since it could potentially have PII or sensitive data
        msg_dict["code"] = "<redacted>"

    event_dict.update(msg_dict)
    # move all the parsed content out to the extra properties and minimize the main message
    event_dict[MESSAGE_KEY] = f"{msg_type} received"
    return event_dict


def custom_ipkernel_format_processor(logger, method_name, event_dict) -> dict:
    """Attempts to format the IPython kernel's log messages in a more readable way
    for both local dev and sending to a log aggregation service.
    """
    msg = event_dict.get(MESSAGE_KEY)
    if not isinstance(msg, str):
        return event_dict

    # strip out all the initial whitespace
    msg = msg.replace("\n", " ").strip()
    event_dict[MESSAGE_KEY] = msg

    if msg.startswith("*** MESSAGE TYPE"):
        # "*** MESSAGE TYPE:<msg_type>***"
        msg_type = msg.replace("*** MESSAGE TYPE:", "").replace("***", "").strip()
        event_dict["msg_type"] = msg_type
        return event_dict

    if msg.startswith("Content:"):
        # "Content: { ... }    --->"
        msg_raw = msg.replace("Content: ", "", 1).replace("--->", "").strip()
        return parse_message(event_dict, msg_raw, msg_type="unk message content")

    # at this point, we should have two main groups of logs we care about parsing:
    # 1. "<msg_type>: {msg_raw}"
    # 2. "{msg_raw}"
    elif not msg.startswith("{"):
        # "execute_request: { ... }"
        try:
            msg_type, msg_raw = msg.split(": ", 1)
            return parse_message(event_dict, msg_raw, msg_type=msg_type)
        except Exception: # noqa
            # possibly a startup log or something we don't care about parsing
            pass

    # { ... }
    return parse_message(event_dict, msg)


def configure_log_formatter():
    """Sets up the log formatter for the IPKernelApp logger, returning the formatter used.
    """
    shared_processors = [
        custom_ipkernel_format_processor,
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    dev_logging = str(os.environ.get("DEV_LOGGING", False)).lower() == "true"
    if dev_logging:
        renderer = structlog.dev.ConsoleRenderer()
    else:
        renderer = structlog.processors.JSONRenderer()

        def rename_event_key(logger, method_name, event_dict):
            """Renames the `event` key to `message`

            This helper function renames the `event` key in structured logging
            entries to `message` key which conforms to Datadog's default
            attribute for log message text.
            """
            event_dict["message"] = event_dict.pop("event")
            return event_dict

        shared_processors.append(rename_event_key)

        # Make uncaught exceptions show up in Datadog as a single log message instead
        # of splitting every line of the stack trace into a separate log message.
        # https://stackoverflow.com/a/69599868/1391176
        logger = structlog.get_logger(__name__)

        def single_line_excepthook(ex_type, ex_value, ex_traceback):
            logger.error(
                "Uncaught exception",
                exception="".join(
                    traceback.format_exception(
                        ex_type,
                        value=ex_value,
                        tb=ex_traceback,
                    )
                ),
                ex_type=ex_type,
                ex_value=ex_value,
                ex_traceback=ex_traceback,
            )

        sys.excepthook = single_line_excepthook

    structlog_processors = [*shared_processors]
    structlog_processors.insert(0, structlog.stdlib.filter_by_level)
    structlog_processors.append(structlog.stdlib.ProcessorFormatter.wrap_for_formatter)

    structlog.configure(
        processors=structlog_processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
    )

    return structlog.stdlib.ProcessorFormatter(
        processor=renderer,
        foreign_pre_chain=shared_processors,
    )
