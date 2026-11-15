import json      # json：把 Python 的数据变成字符串的工具
import hashlib   # hashlib：算指纹（哈希）的工具


def canonical(obj):
    """
    【作用】把数据变成"格式完全固定的字符串"。
    """
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(text):
    """
    【作用】算指纹。用 SHA-256 算法，出来是一串 64 位的十六进制字符。
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()