import pytest
from censor_client.controller import _duplicate_character_checker, _get_censored_string
from censor_client.models import WhitelistDatasets


@pytest.mark.asyncio
async def test_username_underscore():
    dataset = WhitelistDatasets(
        blacklist=set(),
        custom=set(),
        custom_old=set(),
        dictionary=set(),
        nicknames={},
        nicknames_set=set(),
        random_prefixes=set(),
        random_suffixes=set(),
        sorted_datasets=set(),
        trusted_usernames=set(),
        usernames={"test_username"},
        version=0,
    )
    censored_string = await _get_censored_string(dataset, "test_username")
    assert censored_string.censored_words == []


@pytest.mark.parametrize(
    "expected",
    [
        ("qwerty"),
        ("qqwweerrttyy"),
        ("qqwerty"),
        ("qwertyy"),
        ("qwerrty"),
        ("qqwerrty"),
        ("qwerrtyy"),
    ],
)
@pytest.mark.asyncio
async def test_repeated_characters(expected):
    dataset = WhitelistDatasets(
        blacklist=set(),
        custom={expected},
        custom_old=set(),
        dictionary=set(),
        nicknames={},
        nicknames_set=set(),
        random_prefixes=set(),
        random_suffixes=set(),
        sorted_datasets=set(),
        trusted_usernames=set(),
        usernames=set(),
        version=0,
    )
    assert (
        await _duplicate_character_checker(dataset, "qqwwweeeerrrrrttttttyyyyyyy")
        is True
    )

    censored_string = await _get_censored_string(dataset, "qqwwweeeerrrrrttttttyyyyyyy")
    assert censored_string.censored_words == []


@pytest.mark.asyncio
async def test_not_found():
    dataset = WhitelistDatasets(
        blacklist=set(),
        custom=set(),
        custom_old=set(),
        dictionary=set(),
        nicknames={},
        nicknames_set=set(),
        random_prefixes=set(),
        random_suffixes=set(),
        sorted_datasets=set(),
        trusted_usernames=set(),
        usernames=set(),
        version=0,
    )

    censored_string = await _get_censored_string(dataset, "asdf")
    assert censored_string.censored_string == "****"
    assert censored_string.censored_words == ["asdf"]
