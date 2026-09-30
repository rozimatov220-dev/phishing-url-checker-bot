import os
import asyncio
import logging
import base64
import requests
from aiohttp import web
from aiogram import Bot, Dispatcher, types
from aiogram.filters import CommandStart

# API kalitlarni muhit o'zgaruvchilaridan olish
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

bot = Bot(token=TELEGRAM_BOT_TOKEN)
dp = Dispatcher()

def check_url_virustotal(url_to_check: str) -> str:
    """VirusTotal v3 API orqali URL'ni tekshirish funksiyasi"""
    # VirusTotal v3 URL'ni Base64 (padding'larsiz) ko'rinishida qabul qiladi
    url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")
    
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    
    try:
        response = requests.get(endpoint, headers=headers)
        
        # Agar URL ilgari skan qilinmagan bo'lsa, uni birinchi tahlilga yuborish kerak
        if response.status_code == 404:
            scan_url = "https://www.virustotal.com/api/v3/urls"
            data = {"url": url_to_check}
            scan_resp = requests.post(scan_url, headers=headers, data=data)
            if scan_resp.status_code in [200, 201]:
                return "⏳ Havola birinchi marta tekshirilmoqda. Iltimos, 1-2 daqiqadan so'ng qayta yuboring."
            else:
                return "❌ Havolani tahlilga yuborishda xatolik yuz berdi."

        if response.status_code != 200:
            return f"❌ Xatolik yuz berdi (Status code: {response.status_code})"

        res_json = response.json()
        stats = res_json['data']['attributes']['last_analysis_stats']
        
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        
        if malicious > 0:
            verdict = f"🚨 **XAVFLI HAVOLA!**\n\nVirusTotal antiviruslarining **{malicious}** tasi bu havolani zararli/fishing deb topdi."
        elif suspicious > 0:
            verdict = f"⚠️ **SHUBHALI HAVOLA!**\n\n**{suspicious}** ta antivirus bu havolani shubhali deb hisobladi."
        else:
            verdict = f"✅ **XAVFSIZ HAVOLA!**\n\n({harmless} ta antivirus tekshirdi, hech qanday tahdid topilmadi)."

        return verdict

    except Exception as e:
        return f"❌ Tizimda xatolik yuz berdi: {str(e)}"

@dp.message(CommandStart())
async def start_handler(message: types.Message):
    # Foydalanuvchi ma'lumotlarini olish
    first_name = message.from_user.first_name
    username = message.from_user.username
    username_str = f"@{username}" if username else "mavjud emas"

    welcome_text = (
        f"Salom, **{first_name}**! 👋\n"
        f"Sizning Telegram nikiz: **{username_str}**\n\n"
        f"Men Phishing & URL Checker botiman. 🛡️\n"
        f"Manga tekshirmoqchi bo'lgan veb-sayt havolasini (masalan, `https://example.com`) yuboring.\n\n"
        f"───\n"
        f"👨‍💻 Dasturchi: Ro'zmatov Azizbek\n"
        f"📩 Aloqa uchun:500514575"
    )

    await message.answer(welcome_text, parse_mode="Markdown")

@dp.message()
async def analyze_url(message: types.Message):
    user_text = message.text.strip()
    
    # Havola ko'rinishida ekanligini oddiy tekshirish
    if not user_text.startswith(('http://', 'https://')):
        await message.answer("⚠️ Iltimos, to'liq havolani yuboring (masalan: `https://...`).")
        return

    wait_msg = await message.answer("🔍 Havola VirusTotal orqali tekshirilmoqda, kuting...")
    
    # VirusTotal so'rovi vaqt olishi mumkinligi uchun uni alohida thread'da bajaramiz
    loop = asyncio.get_event_loop()
    result_text = await loop.run_in_executor(None, check_url_virustotal, user_text)
    
    await wait_msg.edit_text(result_text, parse_mode="Markdown")

# Render portini aldamchi veb-server bilan ta'minlash funksiyasi
async def handle(request):
    return web.Response(text="Bot is running live!")

async def start_web_server():
    app = web.Application()
    app.router.add_get("/", handle)
    runner = web.AppRunner(app)
    await runner.setup()
    port = int(os.environ.get("PORT", 10000))
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()

async def main():
    logging.basicConfig(level=logging.INFO)
    # Soxta portni ishga tushirish (Render talabi uchun)
    await start_web_server()
    # Botning polling jarayoni
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
