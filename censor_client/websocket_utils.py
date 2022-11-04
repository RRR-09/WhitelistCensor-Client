import json
from asyncio import sleep as async_sleep
from enum import Enum
from os import getenv
from time import time
from typing import Any, Callable, Dict, List

import websockets


class WSFunction(str, Enum):
    AUTH = "AUTH"
    WHITELIST_REQUEST = "WHITELIST_REQUEST"


class WSResponse(str, Enum):
    COMPLETE = "COMPLETE"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    AUTH_FAIL = "AUTH_FAIL"
    WHITELIST_UPDATE = "WHITELIST_UPDATE"


class BackgroundWebsocketProcess:
    def __init__(self, add_temp_data_func, send_twitch_message):
        # Seconds before re-attempting a central server connection
        self.reconnect_delay = 5
        self.client_id = getenv("WS_CLIENT_ID", "")
        self.channel_name = getenv("TWITCH_CHAT_CHANNEL", "")
        self.server_id = getenv("WS_SERVER_ID")
        if self.server_id is None:
            raise ValueError("Server ID not specified")
        self.ws_uri = getenv("WS_SERVER_URL", "")
        self.websocket: Any = None
        self.messages: Dict[str, Dict] = {}
        self.add_temp_data_func: Callable = add_temp_data_func
        self.send_twitch_message_func: Callable = send_twitch_message

    async def is_live(self):
        # TODO: Find criteria for connection drops
        return (
            self.websocket is not None
            and self.websocket.open
            and not (self.websocket.closed)
        )

    async def wait_until_live(self, process, max_attempts=0) -> bool:
        attempts = 0
        while not await self.is_live():
            print(f"[WS {process}] Waiting for connection...")

            attempts += 1
            if max_attempts > 0 and attempts > max_attempts:
                return False

            await async_sleep(self.reconnect_delay)

        return True

    async def get_timestamp(self) -> str:
        return f"msg_{str(time()).replace('.','')}"

    async def wait_for_message(
        self, timestamp: str, seconds_to_timeout: int = 10
    ) -> Dict:
        attempts = 0
        while timestamp not in self.messages:
            attempts += 1
            if attempts > seconds_to_timeout:
                raise ValueError(f"Timed out waiting for message {timestamp}")

            await async_sleep(1)

        return self.messages.pop(timestamp)

    async def whitelist_request(
        self, requests: List[str], message: str, username: str, is_username_req=False
    ):
        # Infinitely check for a word, timeout for a username (so it can be marked failed)
        max_live_check_attempts = 3 if is_username_req else 0
        is_live = await self.wait_until_live(
            "whitelist_request", max_attempts=max_live_check_attempts
        )
        if not is_live:
            raise ValueError("Timed out waiting for connection to go live")

        # Continue with the request
        msg_timestamp = await self.get_timestamp()
        data = {
            "id": self.client_id,
            "timestamp": msg_timestamp,
            "function": WSFunction.WHITELIST_REQUEST,
            "data": {
                "requests": requests,
                "message": message,
                "username": username,
                "is_username_req": is_username_req,
                "channel_name": self.channel_name,
            },
        }
        await self.websocket.send(json.dumps(data))

        response = await self.wait_for_message(msg_timestamp)

        response_client_id = response.get("id")
        if response_client_id != self.client_id:
            raise ValueError(
                f"Response client ID mismatch (found {response_client_id}, expected {self.client_id})"
            )

        response_message = str(response.get("message"))
        if str(response_message) != WSResponse.COMPLETE.value:
            raise ValueError(
                f"Unexpected reponse message (found {response_message}, expected {WSResponse.COMPLETE.value})"
            )

    async def announce_whitelist_update(self, word: str, username: bool):
        if username:
            message = f'[The username "{word}" has been approved.]'
        else:
            message = f'[The word "{word}" has been added to the whitelist.]'
        try:
            await self.send_twitch_message_func(message)
        except Exception as e:
            print(f"[Twitch] Error sending announcement:\n{e}\n\n")

    async def update_whitelist(self, message: Dict):
        # TODO: Implement realtime updates
        server_id = message.get("id")
        if server_id != self.server_id:
            raise ValueError(
                f"Message's server ID mismatch (found {server_id}, expected {self.server_id})"
            )

        data = message.get("data", {})
        if data.get("word") is None:
            raise ValueError(f"Received malformed data, 'word' not found:\n{data}")
        if data.get("is_username") is None or type(data.get("is_username")) != bool:
            raise ValueError(
                f"Received malformed data, 'is_username' not found or not bool:\n{data}"
            )

        word = str(data["word"])
        is_username: bool = data["is_username"]

        dataset_index = "usernames" if is_username else "custom"

        self.add_temp_data_func(dataset_index, word)

        print(f"[WS] Updated temp dataset {dataset_index} with '{word}'.")
        await self.announce_whitelist_update(word, is_username)

    async def establish_connection(self):
        async with websockets.connect(self.ws_uri) as websocket:
            data = {"id": self.client_id, "function": WSFunction.AUTH}

            await websocket.send(json.dumps(data))

            response_raw = await websocket.recv()
            response = json.loads(response_raw)
            print(response)

            response_client_id = response.get("id")
            if response_client_id != self.client_id:
                raise ValueError(
                    f"Response client ID mismatch (found {response_client_id}, expected {self.client_id})"
                )

            response_message = str(response.get("message"))
            if str(response_message) != WSResponse.AUTH_SUCCESS.value:
                raise ValueError(
                    f"Unexpected reponse message (found {response_message}, expected {WSResponse.AUTH_SUCCESS.value})"
                )

            self.websocket = websocket
            try:
                async for raw_message in self.websocket:
                    try:
                        message: Dict = json.loads(str(raw_message))
                        assert type(message) == dict
                    except Exception:
                        print("[WS] Failure in decoding incoming message to JSON")
                        continue

                    print("[WS] Message loop")
                    print(message)

                    if str(message.get("message")) == WSResponse.WHITELIST_UPDATE.value:
                        # Incoming comm from server, skip message queue
                        try:
                            await self.update_whitelist(message)
                        except ValueError as e:
                            print(e)
                        continue

                    timestamp = message.get("timestamp")
                    self.messages[timestamp] = message
                    await async_sleep(0)
            except websockets.exceptions.ConnectionClosedError:
                print("[WS] Connection closed")
                self.websocket = None

    async def main_loop(self):
        while True:
            print("[WS] Main loop")
            if not await self.is_live():
                try:
                    await self.establish_connection()
                    print("[WS] Connection established")
                except Exception as e:
                    print(f"[WS] Failure to establish connection in main loop\n{e}")

            await async_sleep(self.reconnect_delay)
