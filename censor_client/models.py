from enum import Enum
from typing import Dict, List, NamedTuple, Set, TypedDict

from pydantic import BaseModel


class CensoredStringReturn(NamedTuple):
    censored_words: List[str]
    censored_string: str


class RequestCensoredMessage(BaseModel):
    username: str
    message: str


class RequestCensoredMessageReturn(BaseModel):
    """
    A comprehensive response detailing any relevant information about the logic executed during the master censor
    function.
    - `username`: Processed username to use.
    - `message`: Processed message to use.
    - `bot_reply_message`: Replies to the user that ran the command with specified string(s).
    - `send_users_message`: If False, signal that the message is not to be sent.

    """

    username: str
    message: str
    bot_reply_message: List[str] = []
    send_users_message: bool = True


class UsernameWhitelistRequestedStatus(str, Enum):
    NOT_ON_RECORD = "NOT_ON_RECORD"
    NEEDS_MORE_MESSAGES = "NEEDS_MORE_MESSAGES"
    READY_TO_REQUEST = "READY_TO_REQUEST"
    REQUEST_SENT = "REQUEST_SENT"
    FAILED_TO_REQUEST = "FAILED_TO_REQUEST"


class UsernameWhitelistRequestedProfile(TypedDict):
    status: UsernameWhitelistRequestedStatus
    messages: int


# Main-Level Models


class FileDrivenState(TypedDict):
    """
    Non-dataset state variables, written to and read from a local file.
    - `username_whitelist_request_data` A record of usernames either pending approval, or waiting to be able to request.
    Do not use as a infallible source of requested usernames, approved usernames will be purged in the future.
    """

    username_whitelist_request_data: Dict[str, UsernameWhitelistRequestedProfile]


class WhitelistDatasets(TypedDict):
    """
    A total container for all whitelist data.
    - `blacklist` is for known bad words to raise a flag for.
    - `custom_old` is a large, semi-sorted set of all unique words during a year of operation.
    May contain bad/abusable words.
    - `custom` is used for new requests. Appended to during operation.
    - `dictionary` is the English dictionary with most bad/abuseable words removed, as well as duplicates from other
    datasets.
    - `nicknames` is a key-value pair of username -> desired username.
    - `nicknames_set` is a set of both keys and values in 'nicknames', for whitelist purposes
    - `random_prefixes`/`random_suffixes` is used for assigning temporary, safe usernames.
    - `sorted_datasets` is every file in the 'sorted_datasets' folder combined.
    - `trusted_usernames` is a set of all not-banned users who interacted with the project before this
    whitelist system was implemented.
    - `usernames` is used for allowing twitch usernames or mentions of ingame usernames. Appended to during operation.
    """

    blacklist: Set[str]
    custom: Set[str]
    custom_old: Set[str]
    dictionary: Set[str]
    nicknames: Dict[str, str]
    nicknames_set: Set[str]
    random_prefixes: Set[str]
    random_suffixes: Set[str]
    sorted_datasets: Set[str]
    trusted_usernames: Set[str]
    usernames: Set[str]
    version: int


class TempDataset(TypedDict):
    """
    A total container for all whitelist data.
    - `custom` is used for new requests. Appended to during operation.
    - `usernames` is used for allowing twitch usernames or mentions of ingame usernames. Appended to during operation.
    """

    custom: Set[str]
    usernames: Set[str]


class WSFunction(str, Enum):
    WHITELIST_REQUEST = "WHITELIST_REQUEST"


class WSResponse(str, Enum):
    COMPLETE = "COMPLETE"
