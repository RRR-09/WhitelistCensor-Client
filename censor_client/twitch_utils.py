from twitchio.ext import commands
from os import getenv


class TwitchBot(commands.Bot):
    def __init__(self):
        ...

    def manual_init(self):
        super().__init__(
            token=getenv("TWITCH_BOT_TOKEN"),
            prefix="?",
            initial_channels=[getenv("TWITCH_CHAT_CHANNEL")],
        )

    async def event_ready(self):
        print(f"[Twitch] Logged in as | {self.nick} ({self.user_id})")
        await self.send_twitch_message("[Censor Service Connected.]")

    async def send_twitch_message(self, message):
        for channel in self.connected_channels:
            await channel.send(message)
