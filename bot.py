import requests
import base64
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# 🔑 Tokens
TELEGRAM_TOKEN = "8093776603:AAGMhwapmlbsEWxkzaezJiLNdW-hXQpaC-Y"   # Replace with your BotFather token
VIRUSTOTAL_API_KEY = "ca04216d65aae3f368329d8cbfd00e9adc1216667154524d07f43ea2eb0624d2"

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("👋 Send me any link and I’ll check if it’s safe ✅ or dangerous ❌")

async def check_link(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = update.message.text.strip()
    if not url.startswith("http"):
        await update.message.reply_text("⚠️ Please send a valid URL (starting with http/https).")
        return

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    # Step 1: Submit the URL for scanning
    data = {"url": url}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)

    if response.status_code == 200:
        scan_id = response.json()["data"]["id"]

        # Encode URL to get report
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        # Step 2: Fetch Analysis Report
        report = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers).json()

        stats = report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)

        # Build reply
        reply = f"🔗 URL: {url}\n\n"
        reply += f"✅ Harmless: {harmless}\n"
        reply += f"⚠️ Suspicious: {suspicious}\n"
        reply += f"❌ Malicious: {malicious}\n\n"
        reply += f"📊 Full Report: https://www.virustotal.com/gui/url/{scan_id}"

        await update.message.reply_text(reply)
    else:
        await update.message.reply_text("❌ Error checking link. Try again later.")

def main():
    app = Application.builder().token(TELEGRAM_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, check_link))
    print("✅ Bot is running...")
    app.run_polling()

if __name__ == "__main__":
    main()
