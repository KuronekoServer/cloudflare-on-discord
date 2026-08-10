import os

import discord

from cloudcord_adapter import configure

configure(os.environ["CLOUDCORD_ORIGIN"])

intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)


@client.event
async def on_message(message: discord.Message) -> None:
    if message.author == client.user:
        return
    if message.content == "!ping":
        await message.channel.send("pong")


client.run(os.environ["CLOUDCORD_BOT_TOKEN"])
