import json
from os import getenv
from pathlib import Path
from typing import Dict, List, Set

import aiohttp
from dotenv import dotenv_values
from fastapi import BackgroundTasks
from models import (
    CensoredStringReturn,
    FileDrivenState,
    RequestCensoredMessageReturn,
    UsernameWhitelistRequestedProfile,
    UsernameWhitelistRequestedStatus,
    WhitelistDatasets,
)
from websocket_utils import BackgroundWebsocketProcess

MIN_TO_REQUEST_WHITELIST = 2  # Minimum messages to trigger a whitelist request
REMOTE_DATA_PATH = Path("..", "data_remote")  # Synced with remote master
LOCAL_DATA_PATH = Path("..", "data_local")  # Only used and modified locally
FILE_PATHS = {
    "blacklist": REMOTE_DATA_PATH / "blacklist.json",
    "custom_old": REMOTE_DATA_PATH / "custom_old.json",
    "custom": REMOTE_DATA_PATH / "custom.json",
    "dictionary": REMOTE_DATA_PATH / "dictionary.json",
    "nicknames": REMOTE_DATA_PATH / "nicknames.json",
    "random_prefixes": REMOTE_DATA_PATH / "random_prefixes.json",
    "random_suffixes": REMOTE_DATA_PATH / "random_suffixes.json",
    "trusted_usernames": REMOTE_DATA_PATH / "trusted_usernames.json",
    "usernames": REMOTE_DATA_PATH / "usernames.json",
    "sorted_datasets": REMOTE_DATA_PATH / "sorted_datasets",
    "username_request_statuses": LOCAL_DATA_PATH / "username_request_statuses.json",
}


def check_dotenv():
    dotenv_key = ""
    try:
        for dotenv_key in list(dotenv_values(".env.default").keys()):
            if getenv(dotenv_key) is None:
                raise IndexError
    except Exception:
        exception_message = (
            "Could not validate .env file! Does it exist/is it properly formatted?"
        )
        if dotenv_key:
            exception_message = (
                f"Failed when validating '{dotenv_key}' key in .env file! "
                "Does it exist/is it properly formatted?"
            )

        raise Exception(exception_message)


def initialize_datafiles():
    """
    Datafiles may not exist (not included in the repository). Create them if they're missing,
    filling with blank data expected for that file.
    """

    # Create data folders if missing
    REMOTE_DATA_PATH.mkdir(parents=True, exist_ok=True)
    LOCAL_DATA_PATH.mkdir(parents=True, exist_ok=True)

    # { file_path_key: default_value }
    default_data = {
        "blacklist": [],
        "custom_old": [],
        "custom": [],
        "dictionary": [],
        "nicknames": {},
        "random_prefixes": [],
        "random_suffixes": [],
        "trusted_usernames": [],
        "usernames": [],
        "username_request_statuses": {},
    }

    for file_path_key, default_value in default_data.items():
        path = FILE_PATHS[file_path_key]
        if not path.exists():
            print(f"[Initalizing file '{path}']")
            with open(path, "w") as f:
                json.dump(default_value, f)


def load_data() -> WhitelistDatasets:
    base_dataset_paths: List[str] = [
        "blacklist",
        "custom_old",
        "custom",
        "dictionary",
        "random_prefixes",
        "random_suffixes",
        "trusted_usernames",
        "usernames",
    ]
    datasets: Dict[str, Set[str]] = {}

    # Load and set all files
    for dataset_type in base_dataset_paths:
        dataset_path = FILE_PATHS[dataset_type]
        try:
            with open(dataset_path, "r") as f:
                data = json.load(f)
                datasets[dataset_type] = set(data)
        except Exception:
            raise ValueError(f"{dataset_path} malformed or missing")

    # Assemble all files in `sorted_datasets` folder to a single dataset

    datasets["sorted_datasets"] = set()
    for dataset_file in FILE_PATHS["sorted_datasets"].glob("*.json"):
        try:
            with open(dataset_file, "r") as f:
                data = json.load(f)
                datasets["sorted_datasets"].update(set(data))
        except Exception:
            raise ValueError(f"{dataset_file} malformed or missing")

    # Load nicknames and split key-values to a set
    try:
        with open(FILE_PATHS["nicknames"], "r") as f:
            nicknames = json.load(f)
            datasets["nicknames_set"] = set(nicknames.keys()).union(
                set(nicknames.values())
            )
    except Exception:
        raise ValueError(f"{FILE_PATHS['nicknames']} malformed or missing")

    return WhitelistDatasets(
        blacklist=datasets.pop("blacklist"),
        custom=datasets.pop("custom"),
        custom_old=datasets.pop("custom_old"),
        dictionary=datasets.pop("dictionary"),
        nicknames=nicknames,
        nicknames_set=datasets.pop("nicknames_set"),
        random_prefixes=datasets.pop("random_prefixes"),
        random_suffixes=datasets.pop("random_suffixes"),
        sorted_datasets=datasets.pop("sorted_datasets"),
        trusted_usernames=datasets.pop("trusted_usernames"),
        usernames=datasets.pop("usernames"),
        version=0,
    )


def load_state() -> FileDrivenState:
    # USERNAME REQUEST STATUS
    # Many will send one message and leave, require x msgs to bother with a whitelist request
    username_whitelist_requested: Dict[str, UsernameWhitelistRequestedProfile]
    try:
        with open(FILE_PATHS["username_request_statuses"], "r") as f:
            username_whitelist_requested = json.load(f)
    except Exception:
        raise ValueError(
            f"{FILE_PATHS['username_request_statuses']} malformed or missing"
        )

    return FileDrivenState(username_whitelist_request_data=username_whitelist_requested)


async def _word_in_whitelists(ds: WhitelistDatasets, word: str) -> bool:
    # Order of max expected size, least to greatest
    return (
        word in ds["custom"]
        or word in ds["random_prefixes"]
        or word in ds["random_suffixes"]
        or word in ds["nicknames_set"]
        or word in ds["trusted_usernames"]
        or word in ds["usernames"]
        or word in ds["sorted_datasets"]
        or word in ds["custom_old"]
        or word in ds["dictionary"]
    )


async def _get_censored_string(
    ds: WhitelistDatasets, unsafe_string_to_check: str, debug=False
) -> CensoredStringReturn:
    string_to_check = unsafe_string_to_check.encode("ascii", "ignore").decode("ascii")
    censored_words = []
    censored_string_assembly = []
    space_bypassed_string = ""

    def print_if_debug(print_str, is_debug):
        if is_debug:
            print(print_str)

    # punctuation = {"!", "?", ",", ".", ":", ";", "'", '"', "(", ")", "@", "#", "$", "%", "^", "&", "*",}
    for word in string_to_check.split(" "):
        word_is_spaced = False
        original_word = word
        clean_word = "".join(char for char in word if char.isalpha())

        # Handle people trying to space out non-whitelisted words
        if len(clean_word) == 1:
            print_if_debug(f"space_bypassed_string: {clean_word} ({word})", debug)
            space_bypassed_string += clean_word
            continue
        elif len(space_bypassed_string) > 0:
            space_bypassed_censored = space_bypassed_string
            print_if_debug(
                f"space_bypassed_censored assembly: {space_bypassed_string} ({word})",
                debug,
            )
            if space_bypassed_string.strip() != "" and not (
                await _word_in_whitelists(ds, space_bypassed_string.lower())
            ):
                censored_words.append(space_bypassed_string.lower())
                space_bypassed_censored = space_bypassed_string.replace(
                    space_bypassed_string, "*" * len(space_bypassed_string)
                )
            space_bypassed_censored = " ".join(space_bypassed_censored)
            censored_string_assembly.append(space_bypassed_censored)
            space_bypassed_string = ""  # Clear space bypass buffer

        not_empty_or_in_whitelists = (
            clean_word.strip() != ""
            and not await _word_in_whitelists(ds, clean_word.lower())
        )

        # Handle mentions of temp usernames
        is_temp_name = False
        if not_empty_or_in_whitelists:
            clean_word_lower = clean_word.lower()
            for prefix in ds["random_prefixes"]:
                if clean_word_lower.startswith(prefix):
                    potential_suffix = clean_word_lower.replace(prefix, "", 1).strip()
                    # No handling of anything other than the exact phrase, yet
                    if potential_suffix in ds["random_suffixes"]:
                        is_temp_name = True
                        break

        if not is_temp_name and not_empty_or_in_whitelists:
            # Attempt to remove common suffixes (plurals, possessive) and check the whitelist after
            good_with_suffix_change = False
            common_added_suffixes = {"s", "ve", "d", "less"}
            for suffix in common_added_suffixes:
                truncated_word = clean_word.removesuffix(suffix)
                if truncated_word != clean_word:
                    if await _word_in_whitelists(ds, truncated_word.lower()):
                        good_with_suffix_change = True
                        break

            # Attempt to add common suffixes ('g' to 'makin') and check the whitelist after
            common_removed_suffixes = {"g"}
            for suffix in common_removed_suffixes:
                supplemented_word = f"{clean_word}{suffix}"
                if await _word_in_whitelists(ds, supplemented_word.lower()):
                    good_with_suffix_change = True
                    break

            suffix_was_duplicated = False
            if len(clean_word) >= 3 and not good_with_suffix_change:
                print_if_debug(f"cleanword_suffix_check: {clean_word} ({word})", debug)
                # Allow suffix-extended characters, like "testtttttttttttttttt" qualifying as "test"
                offset = 1
                index = len(clean_word) - offset
                while (index > 2) and clean_word[index] == clean_word[index - 1]:
                    word_attempt = clean_word[:index].lower()
                    if await _word_in_whitelists(ds, word_attempt):
                        clean_word = word
                        suffix_was_duplicated = True
                        break
                    offset += 1
                    index = len(clean_word) - offset

            if not good_with_suffix_change and (
                not suffix_was_duplicated or len(clean_word) < 3
            ):
                print_if_debug(f"blacklist_action: {clean_word} ({word})", debug)
                censored_words.append(clean_word.lower())
                previous_asterisks = original_word.count("*")
                clean_word = original_word.replace(clean_word, "*" * len(clean_word))
                if clean_word.count("*") < len(clean_word) - previous_asterisks:
                    # Theres some weird interjecting symbols and we should just censor the whole word
                    clean_word = len(original_word) * "*"
        elif word_is_spaced:
            # If we've checked the non-spaced word is fine,
            # retain the spacing
            clean_word = " ".join(clean_word)
            print_if_debug(f"word_is_spaced: {clean_word} ({word})", debug)
        else:
            # If we're not censoring, leave numbers in
            # clean_word = "".join(char for char in word if char.isalnum())
            print_if_debug(f"not_censoring: {clean_word} ({word})", debug)
            clean_word = word

        censored_string_assembly.append(clean_word)

    # Finish adding any single-char last-words
    if len(space_bypassed_string) > 0:
        clean_word = space_bypassed_string
        original_word = space_bypassed_string
        if clean_word.strip() != "" and not (
            await _word_in_whitelists(ds, clean_word.lower())
        ):
            censored_words.append(clean_word.lower())
            clean_word = original_word.replace(clean_word, "*" * len(clean_word))
        else:
            # retain the spacing
            clean_word = " ".join(clean_word)

        print_if_debug(f"single-char last-words: {clean_word} ({original_word})", debug)
        censored_string_assembly.append(clean_word)

    return CensoredStringReturn(
        censored_words=censored_words,
        censored_string=" ".join(censored_string_assembly),
    )


async def _get_temp_username(ds: WhitelistDatasets, seed_string: str) -> str:
    """
    Returns a random 2-word username, based on the second parameter (seed_string)
    """
    prefixes = sorted(list(ds["random_prefixes"]))
    suffixes = sorted(list(ds["random_suffixes"]))

    seed_string = seed_string.lower().encode("ascii", "ignore").decode("ascii")
    seed_number = sum([ord(char) for char in seed_string])

    prefix = prefixes[seed_number % len(prefixes)]
    suffix = suffixes[seed_number % len(suffixes)]

    return f"{prefix.capitalize()}{suffix.capitalize()}"


async def _user_is_trusted(ds: WhitelistDatasets, username: str) -> bool:
    return username.lower() in ds["trusted_usernames"]


async def _get_user_nickname(ds: WhitelistDatasets, username: str) -> str:
    """
    Returns the user's nickname if it exists, otherwise returns an empty string (falsey)
    """
    return ds["nicknames"].get(username.lower(), "")


async def _username_in_whitelist(ds: WhitelistDatasets, username: str) -> bool:
    username = username.lower()
    if await _word_in_whitelists(ds, username):
        return True

    for word in username.split("_"):
        word = word.lower()
        if not (await _word_in_whitelists(ds, word)):
            return False

    return True


async def _get_blacklisted_words(
    ds: WhitelistDatasets, unsafe_string_to_check: str
) -> List[str]:
    string_to_check = unsafe_string_to_check.encode("ascii", "ignore").decode("ascii")
    blacklisted_words: List[str] = []
    for word in string_to_check.split(" "):
        if word.lower() in ds["blacklist"]:
            blacklisted_words.append(word)

    return blacklisted_words


async def _request_username(
    ws_manager: BackgroundWebsocketProcess,
    state: FileDrivenState,
    username: str,
    message: str,
):
    username_lower = username.lower()
    default_profile = UsernameWhitelistRequestedProfile(
        status=UsernameWhitelistRequestedStatus.NOT_ON_RECORD, messages=0
    )
    profile = state["username_whitelist_request_data"].get(
        username_lower, default_profile
    )
    try:
        await ws_manager.whitelist_request(
            [username_lower], message, username, is_username_req=True
        )
        profile["status"] = UsernameWhitelistRequestedStatus.REQUEST_SENT
    except Exception:
        profile["status"] = UsernameWhitelistRequestedStatus.FAILED_TO_REQUEST

    # Update app state and datafile
    state["username_whitelist_request_data"][username_lower] = profile
    with open(FILE_PATHS["username_request_statuses"], "w") as f:
        json.dump(state["username_whitelist_request_data"], f)


async def _blacklist_alert(
    original_name: str, message: str, blacklisted_words: List[str]
):
    # TODO: Pulled directly from prototype. To be replaced with remote-server discord bot.
    webhook_url = getenv(
        "DISCORD_WEBHOOK_BLACKLIST_ALERT_CHANNEL", ""
    )  # Must exist, verified by `check_dotenv`.

    user_url = f"https://twitch.tv/popout/{getenv('TWITCH_CHAT_CHANNEL')}/viewercard/{original_name.lower()}"

    mention_id = getenv("DISCORD_BLACKLIST_ALERT_USER_ID")
    mention = f"<@{mention_id}>\n" if mention_id else ""

    alert_message = (
        f"[BLACKLIST ALERT]\nUser: `{original_name}`\nMessage: `{message}`\n"
        f"Blacklisted Words: `{', '.join(blacklisted_words)}`\n"
        f"<{user_url}>"
    )

    webhook_data = {
        "content": (
            f"{mention}{alert_message}\n"
            f"<https://twitch.tv/{getenv('TWITCH_CHAT_CHANNEL')}>"
        ),
        "username": "Blacklist Alert",
    }

    async with aiohttp.ClientSession() as session:
        await session.post(webhook_url, data=webhook_data, raise_for_status=True)
        print(f"[Blacklist Alert Sent]\n{alert_message}")


async def _request_username_whitelist(
    state: FileDrivenState, username: str
) -> UsernameWhitelistRequestedStatus:
    """
    Each call of the function progresses a user to the next step of the whitelist request process:
    1. Initial request, notify the user their name is pending
    2. Increment their message count until they meet the requirement (repeats until met)
    3. When requirement is met, send a request.
    4. If last request failed, send again (repeats until successful)
    5. Return and do not alter internal state if request has been sent successfully
    """

    username = username.lower()
    default_profile = UsernameWhitelistRequestedProfile(
        status=UsernameWhitelistRequestedStatus.NOT_ON_RECORD, messages=0
    )
    profile = state["username_whitelist_request_data"].get(username, default_profile)
    new_profile = False

    if profile["status"] == UsernameWhitelistRequestedStatus.REQUEST_SENT:
        # Do not edit state or datafile, this user's process is complete and will not change
        return profile["status"]

    if profile["status"] == UsernameWhitelistRequestedStatus.NOT_ON_RECORD:
        # This is the first known message from them, add to record
        new_profile = True
        profile = UsernameWhitelistRequestedProfile(
            status=UsernameWhitelistRequestedStatus.NEEDS_MORE_MESSAGES, messages=1
        )
    elif profile["status"] == UsernameWhitelistRequestedStatus.NEEDS_MORE_MESSAGES:
        if profile["messages"] + 1 >= MIN_TO_REQUEST_WHITELIST:
            # They have enough messages, change the status
            profile["status"] = UsernameWhitelistRequestedStatus.READY_TO_REQUEST

        # Increment the message counter
        profile["messages"] += 1

    # Update app state and datafile
    state["username_whitelist_request_data"][username] = profile
    with open(FILE_PATHS["username_request_statuses"], "w") as f:
        json.dump(state["username_whitelist_request_data"], f)

    return (
        UsernameWhitelistRequestedStatus.NOT_ON_RECORD
        if new_profile
        else profile["status"]
    )


async def request_censored_message(
    ds: WhitelistDatasets,
    state: FileDrivenState,
    username: str,
    message: str,
    ws_manager: BackgroundWebsocketProcess,
    background_tasks: BackgroundTasks,
) -> RequestCensoredMessageReturn:
    """
    Master censor function. Handles all automatic background logic related to the whitelist censor system.
    """
    nickname = await _get_user_nickname(ds, username)
    if await _user_is_trusted(ds, username):
        # Beyond nickname, these users do not need to bother with the censor system.
        return RequestCensoredMessageReturn(
            username=nickname or username, message=message
        )

    original_name = username
    censored_name = nickname or original_name
    reply_message: List[str] = []

    # Check username
    if not (nickname or await _username_in_whitelist(ds, original_name)):
        # Username not safe, we need to get a temp username and potentially request a whitelist.
        censored_name = await _get_temp_username(ds, original_name)
        whitelist_requested_status = await _request_username_whitelist(state, username)
        if whitelist_requested_status == UsernameWhitelistRequestedStatus.NOT_ON_RECORD:
            reply_message.append(
                f"[Assigning random username '{censored_name}'. Your real username "
                f"'{original_name}' is pending approval.]"
            )
        elif whitelist_requested_status in {
            UsernameWhitelistRequestedStatus.READY_TO_REQUEST,
            UsernameWhitelistRequestedStatus.FAILED_TO_REQUEST,
        }:
            background_tasks.add_task(
                _request_username, ws_manager, state, username, message
            )

    # Check if message contains blacklisted words
    blacklisted_words = await _get_blacklisted_words(ds, message)
    if blacklisted_words:
        reply_message.append(
            f"[You've attempted to send a message with blacklisted words ({', '.join(blacklisted_words)}).]"
        )

        background_tasks.add_task(
            _blacklist_alert, original_name, message, blacklisted_words
        )

        return RequestCensoredMessageReturn(
            username=censored_name,
            message=message,
            bot_reply_message=reply_message,
            send_users_message=False,
        )

    # Censor the message, requesting whitelist if needed
    censored_words, censored_string = await _get_censored_string(ds, message)

    if censored_words:
        reply_message.append(
            f"[Some words you used are not in the whitelist for new users and have been sent for "
            f"approval ({', '.join(censored_words)})]"
        )
        background_tasks.add_task(
            ws_manager.whitelist_request, censored_words, message, original_name
        )

    return RequestCensoredMessageReturn(
        username=censored_name,
        message=censored_string,
        bot_reply_message=reply_message,
    )
