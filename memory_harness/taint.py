import re
import unicodedata

def norm_text(s):
    """
    【作用】把文字"标准化"，方便比对。
    【做了什么】
      1. 全角字符转半角（Ａ→A，！→!）
      2. 去掉首尾空白，中间连续空格压成一个
      3. 全部转小写（Apple 和 apple 视为一样）
    【为什么】攻击者会用大小写、空格、全角字符来绕过比对。
    """
    s = unicodedata.normalize("NFKC", str(s)).strip().lower()
    return re.sub(r"\s+", " ", s)


def norm_path(p):
    """
    【作用】把路径"标准化"。
    【做了什么】反斜杠转正斜杠、去掉 /./、把 /a/b/../c 变成 /a/c
    【为什么】/var/log/app 和 /var//log/./app 和 /var/log/x/../app
    是同一个路径，但字符串长得不一样，不标准化就比对不出来。
    """
    p = norm_text(p).replace("\\", "/")
    p = re.sub(r"/+", "/", p)
    # 核心：处理路径里的“任意门”
    # /var/log/x/../app 其实是 /var/log/app
    # 如果不处理，黑客就能用 .. 绕过比对
    parts = []
    for seg in p.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts:
                parts.pop()
            continue
        parts.append(seg)

    return "/" + "/".join(parts)


def norm_value(v):
    """
    【作用】根据值的类型，走不同的标准化路线。
    纯数字 → 统一成 4 位小数（1 和 1.0 和 1.00 视为一样）
    带斜杠 → 当路径处理
    其他   → 当普通文字处理
    """
    s = norm_text(v)

    if re.fullmatch(r"-?\d+(\.\d+)?", s):
        return f"{float(s):.4f}"

    if "/" in s or "\\" in s:
        return norm_path(s)

    return s


def levenshtein(a, b, cap=2):
    """
    【作用】算两个字符串的"编辑距离"——要改几个字符才能变成另一个。
    例："abc" 和 "abd" 距离是 1（改一个字符）。

    【cap 参数】最多只关心 2 个字符以内的差异，超过就直接返回 cap+1。
    这是为了加速：我们只需要判断"是不是很像"，不需要知道"差多少"。
    """
    if abs(len(a) - len(b)) > cap:
        return cap + 1

    prev = list(range(len(b) + 1))

    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(
                prev[j] + 1,              # 删除
                cur[j - 1] + 1,           # 插入
                prev[j - 1] + (ca != cb)  # 替换（相同则不加）
            ))
        prev = cur
        if min(prev) > cap:
            return cap + 1

    return prev[-1]


def hard_taint(values, untrusted_texts):
    """
    【作用】硬污点判定。四类匹配，任一命中就算硬污点。

    【为什么要四类匹配】
    攻击者可能用各种变形绕过单一规则：
      子串匹配   —— 最直接，参数原样出现在不可信文本里
      近似匹配   —— 攻击者改一两个字符（比如把 / 改成 \\），距离还是很小
      实体匹配   —— 换一种写法但指的是同一个东西（这个版本实现从简）
      片段组合   —— 参数由文本里好几处片段拼起来（比如"文件"+"路径"分开出现）

    【返回】(是否是硬污点, 原因说明)
    """
    if not untrusted_texts:
        return False, ""

    texts = [norm_text(t)[:600] for t in untrusted_texts]

    for v in values:
        if v is None:
            continue

        nv = norm_value(v)

        if len(nv) < 2:
            continue

        for t in texts:
            # 第一类：子串匹配。参数值直接出现在不可信文本里
            if nv in t or str(v) in t:  # 【修复 Bug】加上了原始值 str(v) 的比对
                return True, f"子串匹配：参数值“{v}”直接取自不可信文本"

        # 第二类：近似匹配。只对足够长的参数值做，太短的容易误判
        if len(nv) >= 8:
            cap = 2
            for t in texts:
                for seg_len in (len(nv), len(nv) + 1, len(nv) + 2):
                    for i in range(0, max(1, len(t) - seg_len + 1)):
                        if levenshtein(nv, t[i:i + seg_len], cap) <= cap:
                            return True, f"近似匹配：参数值“{v}”与不可信文本片段高度接近"

        # 第四类：片段组合匹配
        # 把参数值按分隔符切成几块，如果有两块以上分别出现在文本的不同位置，
        # 说明这个参数是由文本里多处内容拼出来的（攻击者的常见手法）
        frags = [f for f in re.split(r"[\\/\-_.\s:;,|]+", nv) if len(f) >= 3]
        if len(frags) >= 2:
            for t in texts:
                if sum(1 for f in frags if f in t) >= 2:
                    return True, f"片段组合匹配：参数值“{v}”的多个片段分别命中不可信文本"

    return False, ""


def classify_taint(values, untrusted_texts):
    """
    【作用】最终裁决：这段上下文属于哪一级？

    【三种结果】
      "none" —— 上下文里根本没有不可信消息（最干净，可以生成主经验）
      "hard" —— 参数是从不可信文本抄的（一律拒绝）
      "soft" —— 有不可信消息，但参数不是抄的（生成候选经验）

    【注意判定顺序】先判硬污点，再判软污点。
    这个顺序很重要：必须"宁多判候选、不漏判硬污点"。
    漏掉一个硬污点，就等于放了一个后门进来。
    """
    if not untrusted_texts:
        return "none", "证据集合内无不可信消息"

    ok, why = hard_taint(values, untrusted_texts)
    if ok:
        return "hard", why

    return "soft", "存在不可信消息，但参数值与之不构成直接嵌入"