import re
import os
import requests
from dotenv import load_dotenv
import discord
import json
import datetime

load_dotenv()

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
BOT_TOKEN = os.environ.get("BOT_TOKEN")

# bot configuration
intents = discord.Intents.default()
intents.message_content = True
intents.messages = True
intents.members = True
client = discord.Client(intents=intents)

def scan_message(message):
    message = str(message)
    scan_url = "https://www.virustotal.com/api/v3/urls"

    headers = {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    analysis_header={
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    arrayOfWords = message.split(" ")
    for a in arrayOfWords:
        x = re.search(r"http\S+", a)
        if(x and len(a) > 8 ):
            link = x.group()
            if(link[:5] != "https"):
                return True
            else:
                # try:
                response = requests.post(scan_url, headers=headers, data={"url": link})
                scan_data = json.loads(response.text)
                try:
                    analysis_id = scan_data["data"]["id"]
                    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                    analysis_response = requests.get(analysis_url, headers=analysis_header)
                    try:
                        analysis_data = json.loads(analysis_response.text)
                        stats = analysis_data["data"]["attributes"]["stats"]
                        if(stats['malicious'] >= 1 or stats['suspicious'] >=3):
                            return True

                    except:
                        print(f"Encountered error: {analysis_response.text}")
                        return False
                except:
                    print(f"Encountered error: {response.text}")
                    return False
    return False

@client.event
async def on_message(message):
    if message.author != client.user:
        malicious = scan_message(message=message.content)
        if malicious:
            await message.delete()
            await message.channel.send(f"User <@{message.author.id}> sent a potential malicious link!")
            # member = message.author
            # if isinstance(member, discord.Member):
            #     await member.timeout(datetime.timedelta(hours=1), reason=f"Sent a malicious link")

@client.event
async def on_ready():
    print("Connected to Discord uwu haha app")
    await client.change_presence(activity=discord.Game("Scanning for bad link"))

if __name__ == "__main__":  
    client.run(BOT_TOKEN)
            
