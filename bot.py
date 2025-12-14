import os
import time
import hmac
import hashlib
import secrets
import re
import asyncio
import discord
from discord import app_commands

# =========================
# CONFIG (ENV)
# =========================
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN", "")
SECRET_KEY = os.getenv("SECRET_KEY", "")

GUILD_ID = int(os.getenv("GUILD_ID", "0"))
LINK_CHANNEL_ID = int(os.getenv("LINK_CHANNEL_ID", "0"))
AUTHORIZED_ROLE_ID = int(os.getenv("AUTHORIZED_ROLE_ID", "0"))

TTL_SECONDS = int(os.getenv("TTL_SECONDS", "300"))           # 5 min
COOLDOWN_SECONDS = int(os.getenv("COOLDOWN_SECONDS", "30"))  # 30 sec
MAX_ATTEMPTS = int(os.getenv("MAX_ATTEMPTS", "3"))

if not DISCORD_TOKEN or not SECRET_KEY or GUILD_ID == 0 or LINK_CHANNEL_ID == 0 or AUTHORIZED_ROLE_ID == 0:
    raise RuntimeError(
        "Missing ENV vars. Required: DISCORD_TOKEN, SECRET_KEY, GUILD_ID, LINK_CHANNEL_ID, AUTHORIZED_ROLE_ID."
    )

# =========================
# In-memory state
# pending[user_id] = {"nonce": "123456", "created": epoch, "attempts": 0, "cooldown": epoch}
# =========================
pending: dict[int, dict] = {}

# =========================
# Code generation (digits-only)
# ACCESS: 8 digits = nonce(6) + sig(2)
# ID/RESP: 6 digits (game shows as B-123456; bot ignores prefix)
# =========================
def _hmac_u32(msg: str) -> int:
    digest = hmac.new(SECRET_KEY.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).digest()
    return int.from_bytes(digest[:4], "big", signed=False)

def make_access_key(nonce6: str) -> str:
    sig2 = _hmac_u32(f"CHAL|{nonce6}") % 100  # 00..99
    return f"{nonce6}{sig2:02d}"

def make_response_code(nonce6: str) -> str:
    r6 = _hmac_u32(f"RESP|{nonce6}") % 1_000_000  # 000000..999999
    return f"{r6:06d}"

def format_access(access8: str) -> str:
    return f"{access8[:4]} {access8[4:]}"

def is_expired(created: float) -> bool:
    return (time.time() - created) > TTL_SECONDS

def extract_6digits(text: str) -> str:
    digits = re.sub(r"\D", "", text)
    return digits if len(digits) == 6 else ""

def _time_left(created: float) -> int:
    left = int(TTL_SECONDS - (time.time() - created))
    return max(left, 0)

# =========================
# Discord bot setup
# =========================
intents = discord.Intents.default()
client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)

guild_obj = discord.Object(id=GUILD_ID)

evacom = app_commands.Group(name="evacom", description="Evacom™ authorization commands")

async def guard(interaction: discord.Interaction) -> bool:
    if interaction.guild is None or interaction.guild_id != GUILD_ID:
        await interaction.response.send_message("Use this command inside the server.", ephemeral=True)
        return False

    if interaction.channel_id != LINK_CHANNEL_ID:
        await interaction.response.send_message(
            "Authorization is only available in the Evacom™ link channel.",
            ephemeral=True
        )
        return False

    return True

@evacom.command(name="link", description="Get an ACCESS KEY to authorize Evacom™ in-game.")
async def evacom_link(interaction: discord.Interaction):
    if not await guard(interaction):
        return

    guild = interaction.guild
    assert guild is not None

    role = guild.get_role(AUTHORIZED_ROLE_ID)
    if role is None:
        await interaction.response.send_message("Bot misconfigured: Authorized role not found.", ephemeral=True)
        return

    member = interaction.user
    if isinstance(member, discord.Member) and role in member.roles:
        await interaction.response.send_message("Evacom™ status: already authorized.", ephemeral=True)
        return

    now = time.time()
    st = pending.get(interaction.user.id)

    if st and st.get("cooldown", 0) > now:
        wait = int(st["cooldown"] - now)
        await interaction.response.send_message(f"Please wait {wait}s and try again.", ephemeral=True)
        return

    if st and not is_expired(st["created"]):
        access = make_access_key(st["nonce"])
        st["cooldown"] = now + COOLDOWN_SECONDS
        left = _time_left(st["created"])
        await interaction.response.send_message(
            f"ACCESS KEY: `{format_access(access)}`\n"
            f"Submit the key in the Evacom™ Service Console to receive your Evacom™ ID (example: B-123456`)\n"
            f"Key expires in {left}s.",
            ephemeral=True
        )
        return

    nonce = f"{secrets.randbelow(1_000_000):06d}"
    pending[interaction.user.id] = {
        "nonce": nonce,
        "created": now,
        "attempts": 0,
        "cooldown": now + COOLDOWN_SECONDS,
    }

    access = make_access_key(nonce)
    await interaction.response.send_message(
        f"ACCESS KEY: `{format_access(access)}`\n"
        f"Enter it in-game to receive your Evacom™ ID (example: `B-123456`).\n"
        f"Expires in {TTL_SECONDS}s.",
        ephemeral=True
    )

@evacom.command(name="verify", description="Verify your Evacom™ ID from the game (e.g., B-123456).")
@app_commands.describe(code="Your Evacom™ ID from the game, e.g. B-123456")
async def evacom_verify(interaction: discord.Interaction, code: str):
    if not await guard(interaction):
        return

    st = pending.get(interaction.user.id)
    if not st:
        await interaction.response.send_message("No active session. Use `/EVACOM LINK` first.", ephemeral=True)
        return

    if is_expired(st["created"]):
        pending.pop(interaction.user.id, None)
        await interaction.response.send_message("Session expired. Use `/EVACOM LINK` to get a new ACCESS KEY.", ephemeral=True)
        return

    if st["attempts"] >= MAX_ATTEMPTS:
        pending.pop(interaction.user.id, None)
        await interaction.response.send_message("Too many attempts. Use `/EVACOM LINK` to start again.", ephemeral=True)
        return

    digits = extract_6digits(code)
    if not digits:
        st["attempts"] += 1
        await interaction.response.send_message("Invalid format. Expected like `B-123456`.", ephemeral=True)
        return

    expected = make_response_code(st["nonce"])
    if digits != expected:
        st["attempts"] += 1
        tries_left = max(MAX_ATTEMPTS - st["attempts"], 0)
        await interaction.response.send_message(
            f"Wrong Evacom™ ID. Check digits and try again. Attempts left: {tries_left}.",
            ephemeral=True
        )
        return

    guild = interaction.guild
    assert guild is not None

    role = guild.get_role(AUTHORIZED_ROLE_ID)
    if role is None:
        await interaction.response.send_message("Bot misconfigured: Authorized role not found.", ephemeral=True)
        return

    member = interaction.user
    if not isinstance(member, discord.Member):
        member = await guild.fetch_member(interaction.user.id)

    await member.add_roles(role, reason="Evacom™ authorized")
    pending.pop(interaction.user.id, None)

    await interaction.response.send_message("Your Evacom™ successfully authorized. Community Status updated: **AUTHORIZED**", ephemeral=True)

async def cleanup_loop():
    await client.wait_until_ready()
    while not client.is_closed():
        now = time.time()
        expired_users = [uid for uid, st in pending.items() if (now - st["created"]) > TTL_SECONDS]
        for uid in expired_users:
            pending.pop(uid, None)
        await asyncio.sleep(30)

@client.event
async def setup_hook():
    # Guild-only commands (instant)
    tree.add_command(evacom, guild=guild_obj)
    await tree.sync(guild=guild_obj)
    asyncio.create_task(cleanup_loop())

@client.event
async def on_ready():
    print(f"Logged in as {client.user} | ready")

client.run(DISCORD_TOKEN)
