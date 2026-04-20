import json
from urllib import parse, request


class TelegramDeliveryError(RuntimeError):
    pass


def send_telegram_message(*, bot_token: str, chat_id: str, text: str, timeout: int = 10):
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = parse.urlencode({"chat_id": chat_id, "text": text}).encode("utf-8")
    req = request.Request(url=url, data=payload, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with request.urlopen(req, timeout=timeout) as response:
        body = response.read().decode("utf-8")
    data = json.loads(body)
    if not data.get("ok"):
        raise TelegramDeliveryError(data.get("description") or "Telegram API error")
