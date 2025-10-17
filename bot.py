import re
import os
import json
import aiohttp
import asyncio
import discord
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
BOT_TOKEN = os.getenv("BOT_TOKEN")

intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)

# Queue for background scans
scan_queue = asyncio.Queue()

async def scan_link(link):
    scan_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(scan_url, headers=headers, data={"url": link}) as resp:
            scan_data = await resp.json()
            if "data" not in scan_data:
                print("Invalid VirusTotal response:", scan_data)
                return False

            analysis_id = scan_data["data"]["id"]
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

            for _ in range(3):
                await asyncio.sleep(5)
                async with session.get(analysis_url, headers=headers) as analysis_resp:
                    analysis_data = await analysis_resp.json()
                    try:
                        status = analysis_data["data"]["attributes"]["status"]
                        if status == "completed":
                            stats = analysis_data["data"]["attributes"]["stats"]
                            if stats['malicious'] >= 1 or stats['suspicious'] >= 3:
                                return True
                            else:
                                return False
                    except KeyError:
                        print("Unexpected format:", analysis_data)
                        return False
    return False

async def scan_worker():
    await client.wait_until_ready()
    print("Scan worker started")

    while not client.is_closed():
        message = await scan_queue.get()
        content = message.content
        author = message.author
        channel = message.channel

        urls = re.findall(r"http\S+", content)
        for url in urls:
            if not url.startswith("https"):
                malicious = True
            else:
                malicious = await scan_link(url)

            if malicious:
                try:
                    await message.delete()
                    await channel.send(f"User <@{author.id}> sent a potential malicious link!")
                except Exception as e:
                    print(f"Error deleting message: {e}")
            else:
                print(f"Message from {author} is safe.")

        scan_queue.task_done()

@client.event
async def on_message(message):
    if message.author == client.user:
        return
    if "http" in message.content:
        await scan_queue.put(message)
        print(f"Queued message from {message.author} for scanning.")

@client.event
async def on_ready():
    print(f"Logged in as {client.user} uwu")
    await client.change_presence(activity=discord.Game("Scanning links in background"))
    client.loop.create_task(scan_worker())

if __name__ == "__main__":
    client.run(BOT_TOKEN)
