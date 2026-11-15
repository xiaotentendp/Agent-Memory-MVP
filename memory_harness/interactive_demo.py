"""
交互式演示：智能体经验记忆的可信写入与衰减

【和 demo.py 的关系】
  demo.py  = 自动化自检，九个场景跑一遍，看 [通过]/[失败]
  本文件   = 交互式演示，由你手动输入，逐步看到每一步在拦什么

【本文件相对初版的三处修正】
  1. 可信任务由操作者声明，不再从模型输出里抄（否则"任务不匹配"检查形同虚设）
  2. 执行结果由操作者选择，不再假装"执行成功"
  3. 增加"篡改测试"和"调用经验"两个演示项
"""

import os
import sys

# 让 Windows 终端能显示颜色。不加这句，老版本 cmd 里会显示成 ←[91m 这样的乱码
if os.name == "nt":
    os.system("")

import json
import tempfile
import time

import gateway
import inject
import llm
import store as store_mod
import weights as W
from taint import classify_taint

# ---------------- 配置 ----------------

BASELINE = {"moving": True, "forbid_when_moving": ["open_door"]}

WHITELIST = ["open_window", "close_window", "open_door", "adjust_temp",
             "reduce_feed", "increase_feed", "clean_logs"]

RANGES = {"open_window": (0, 100), "close_window": (0, 100),
          "reduce_feed": (0, 120), "increase_feed": (0, 120),
          "adjust_temp": (16, 30)}

# 可信任务预设。
# 【为什么要这个】专利里任务是由"受信任调用方"下发的，不是模型自己定的。
# 演示时必须把"任务"和"模型的提议"分开，否则两者永远一致，
# "任务不匹配"这道防线就演示不出来。
TASK_PRESETS = [
   ("1", {"action": "browse_weather", "target": "天气", "tag": "查询", "intent": "查看天气"}),
    ("2", {"action": "open_window", "target": "车窗", "tag": "通风", "intent": "通风"}),
    ("3", {"action": "adjust_temp", "target": "空调", "tag": "调温", "intent": "调温"}),
    ("4", {"action": "open_window", "target": "car_window", "tag": "通风", "intent": "通风(英文对象)"}), # 加这个
]

# 【修改】把数据库固定存放在当前目录下的 data 文件夹中
DEMO_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
if not os.path.exists(DEMO_DIR):
    os.makedirs(DEMO_DIR)

DB_PATH = os.path.join(DEMO_DIR, "memory.db")

# 【可选】为了防止每次重启测试数据污染，如果你想每次都是干净的全新库，可以取消下面两行的注释
# if os.path.exists(DB_PATH):
#     os.remove(DB_PATH)

st = store_mod.Store(DB_PATH)
print(f"📁 本地数据库已锁定在: {DB_PATH}")

# 颜色（只是让演示好看，不影响逻辑）
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"


def header(title):
    print("\n" + "=" * 62)
    print(f"  {title}")
    print("=" * 62)


def pick_task():
    """让操作者选一个当前的可信任务（模拟受信任调用方下发任务）"""
    print("\n  当前的可信任务是？")
    for k, t in TASK_PRESETS:
        print(f"    [{k}] {t['intent']}（动作 {t['action']}，对象 {t['target']}）")
    while True:
        c = input("  >> ").strip()
        for k, t in TASK_PRESETS:
            if c == k:
                return t
        print("  输入无效，请重选。")


# ---------------- 主流程：一次交互 ----------------

def run_once(source):
    """
    【一次完整交互】模型提议 → 污点检查 → 网关 → 执行 → 沉淀
    source: "trusted" 或 "untrusted"
    """

    # 外部输入时，先声明可信任务；可信输入时，任务就是用户自己说的话
    if source == "untrusted":
        print("\n  【前提】这段内容来自外部网页/邮件，不是用户指令。")
        print("  【前提】因此需要先声明：用户当前真正要做的任务是什么。")
        task = pick_task()
    else:
        task = None   # 后面从可信输入里取

    text = input("\n  请输入内容 >> ").strip()
    if not text:
        return

    messages = [{"source": source, "text": text}]

    # ---- 第 1 步：模型提议 ----
    print(f"\n{CYAN}[1/4] 正在询问大模型……{RESET}")

    # 【新增】：检查库里有没有被隔离的失败经验
    failed_ptrs = st.list_pointers(include_quarantined=True)
    warning_text = ""
    for p in failed_ptrs:
        if p["quarantined"] == 1 and p["tag"] == "通风":
            trigger = p['summary'].split("｜")[0].replace("触发：", "")
            if trigger in text:
                warning_text = f"【警告】系统记录显示，之前遇到“{trigger}”时，执行 {p['action']} 动作屡次失败，已被列入黑名单。请千万不要再提议 {p['action']}，请尝试其他调节车内环境的方式（比如开空调）。"
                print(f"  {YELLOW}[反思注入] 检测到历史失败经验，已向大模型注入警告。{RESET}")

    # 把警告拼接到用户输入前面，喂给大模型
    llm_input = text
    if warning_text:
        llm_input = f"{warning_text}\n用户输入：{text}"
        # 临时修改 llm 的调用（或者可以直接改 messages 里的 text）
        messages = [{"source": source, "text": llm_input}]

    # 【修改调用，接收 thought】
    proposal, raw, err, thought = llm.propose_action(messages)

    # 【打印思考过程】
    if thought:
        print(f"  {CYAN}[大模型思考过程]{RESET}")
        # 将思考过程按行打印，并加上前缀，显得极其专业
        for line in thought.split('\n'):
            if line.strip():
                print(f"    💭 {line.strip()}")
        print("    " + "-" * 40)

    if proposal is None:
        print(f"  {RED}模型未能给出有效提议：{err}{RESET}")
        if raw:
            print(f"  原始输出（节选）：{raw[:200]}")
        print("  → 不生成经验。这是正确行为：没有可靠提议，就没有经验。")
        return

    if proposal.get("action") == "none":
        print(f"  {YELLOW}模型表示无法判断该做什么。{RESET}")
        print("  → 不生成经验。")
        return

    print(f"  模型提议：动作={proposal['action']}，对象={proposal['action_obj']}，"
          f"参数={proposal['params']}")

    # 可信输入时，用户自己的话就是任务；这里把模型的解读当作"可信侧解析结果"
    if task is None:
        task = {"action": proposal["action"], "target": proposal["action_obj"],
                "tag": "默认", "intent": text[:20]}

    # ---- 第 2 步：污点检查 ----
    print(f"\n{CYAN}[2/4] 污点检查（参数值是否取自不可信文本）{RESET}")

    untrusted = [m["text"] for m in messages if m["source"] != "trusted"]
    values = [proposal["action_obj"]] + [str(v) for v in proposal["params"].values()]
    level, why = classify_taint(values, untrusted)

    if level == "hard":
        print(f"  {RED}[拦截] 硬污点：{why}{RESET}")
        print("  → 本次交互不生成任何经验，只写入审计日志。")
        st.append_log("blocked", {"stage": "taint_hard", "why": why,
                                  "text": text, "proposal": proposal})
        return
    elif level == "soft":
        print(f"  {YELLOW}[警告] 软污点：{why}{RESET}")
        print("  → 参数不是抄来的，但上下文里有不可信内容，只能存为候选经验。")
    else:
        print(f"  {GREEN}[安全] 证据集合内没有不可信内容。{RESET}")

    # ---- 第 3 步：网关 ----
    print(f"\n{CYAN}[3/4] 安全网关（白名单 / 安全基线 / 参数区间 / 任务匹配）{RESET}")

    ok, kind, msg = gateway.gateway_check(
        action=proposal["action"], action_obj=proposal["action_obj"],
        params=proposal["params"], task=task,
        baseline=BASELINE, whitelist=WHITELIST, ranges=RANGES)

    if not ok:
        if kind == "self_unsafe":
            print(f"  {RED}[拦截] {msg}{RESET}")
            print("  → 归因：经验自身不安全。不生成经验。")
        else:
            print(f"  {RED}[拦截] {msg}{RESET}")
            print(f"  → 归因：任务不匹配（当前任务是「{task['intent']}」）。不生成经验，"
                  f"也不影响任何已有经验。")
        st.append_log("blocked", {"stage": "gateway", "kind": kind,
                                  "msg": msg, "task": task, "proposal": proposal})
        return
    else:
        print(f"  {GREEN}[安全] 网关校验通过。{RESET}")

    # ---- 第 4 步：执行（模拟） ----
    print(f"\n{CYAN}[4/4] 执行（本演示为模拟执行，不接真实执行机构）{RESET}")
    print("  请选择执行结果：")
    print("    [1] 执行成功")
    print("    [2] 动作性失败（如执行机构回执未到位）")
    print("    [3] 环境性失败（如雨量联锁、设备忙）")
    c = input("  >> ").strip()

    if c == "2":
        print(f"  {RED}执行失败（动作性）。→ 本次交互不生成经验。{RESET}")
        st.append_log("exec_fail", {"proposal": proposal, "kind": "action"})
        return
    if c == "3":
        print(f"  {YELLOW}执行失败（环境性）。→ 本次交互不生成经验。{RESET}")
        st.append_log("exec_fail", {"proposal": proposal, "kind": "env"})
        return

    # ---- 沉淀经验 ----
    ptr_kind = "candidate" if level == "soft" else "primary"

    seq, _ = st.append_log("interaction", {
        "messages": messages, "action": proposal["action"],
        "action_obj": proposal["action_obj"], "params": proposal["params"],
        "task": task, "proposed_by": "llm"})

    ptr = {
        "ptr_id": f"p{len(st.list_pointers(include_quarantined=True)) + 1:03d}",
        "log_seq": seq,
        "kind": ptr_kind,
        "summary": f"触发：{text[:24]}｜动作：{proposal['action']} "
                   f"{proposal['action_obj']} {proposal['params']}",
        "intent": task["intent"],
        "action": proposal["action"],
        "action_obj": proposal["action_obj"],
        "params": json.dumps(proposal["params"], ensure_ascii=False, sort_keys=True),
        "tag": task["tag"],
        "domain": "vehicle",
        "weight": W.INIT_W,
        "tier": W.tier_of(W.INIT_W),
        "version": 1,
        "created_ts": store_mod.now(),
        "last_success_ts": store_mod.now(),
        "quarantined": 0,
        "unstable": 0,
        "cooldown_count": 0,
        "taint_src": "untrusted" if level == "soft" else None,
    }

    saved = st.save_pointer(ptr)
    tag = "主经验" if ptr_kind == "primary" else "候选经验（不参与自动检索）"
    print(f"\n  {GREEN}[成功] 已固化为{tag}。编号 {saved['ptr_id']}，"
          f"权重 {saved['weight']}（档位 {saved['tier']}）{RESET}")


# ---------------- 查看经验库 ----------------

def show_memory():
    header("当前中层经验库")
    ptrs = st.list_pointers(include_quarantined=True)
    if not ptrs:
        print("  暂无任何经验记录——这本身就是一个结论：被拦下的交互没有留下任何痕迹。")
        return

    for p in ptrs:
        ok, recomputed, anchor = st.verify_pointer(p["ptr_id"])
        status = "隔离" if p["quarantined"] else "可用"
        hash_mark = f"{GREEN}哈希一致{RESET}" if ok else f"{RED}哈希不一致{RESET}"
        print(f"\n  [{p['ptr_id']}] {p['kind'].upper()}｜权重 {p['weight']}"
              f"（{p['tier']}）｜{status}｜{hash_mark}")
        print(f"       {p['summary']}")
        if p["taint_src"]:
            print(f"       污点来源：{p['taint_src']}")


# ---------------- 调用经验（演示归因与衰减） ----------------

def call_existing():
    """
    【这一段演示专利最核心的部分】
    调用一条已存经验，按归因结果分别处置。
    三种归因，三种完全不同的处置：
      - 经验自身不安全 → 直接隔离（不经过降权）
      - 任务不匹配     → 什么都不改
      - 执行失败       → 分环境性/动作性，只有后者扣分
    """
    header("调用一条已有经验（演示归因三分与权重衰减）")

    ptrs = st.list_pointers(include_quarantined=False)
    if not ptrs:
        print("  当前没有可用经验。请先通过「可信输入」积累一条。")
        return

    print(f"\n  {GREEN}当前中层记忆库（可用经验列表）：{RESET}")
    # 直接把所有经验平铺展示出来
    for p in ptrs:
        trigger_text = p['summary'].split("｜")[0].replace("触发：", "")
        print(f"  [{p['ptr_id']}] 触发词：「{trigger_text}」")
        print(f"       动作：{p['action']} {p['action_obj']} {p['params']}｜当前权重 {p['weight']}")

    pid = input("\n  请输入要调用的经验编号 (直接回车默认选第一条) >> ").strip()
    
    # 防呆：如果直接回车，就默认选列表里的第一条
    if not pid:
        pid = ptrs[0]['ptr_id']
        print(f"  (未输入编号，默认选择：{pid})")

    p = st.get_pointer(pid)
    if not p:
        print("  编号不存在。")
        return

    if p["quarantined"]:
        print("  该经验已隔离，跳过。")
        return

    task = pick_task()
    print("\n  请选择执行结果：")
    print("    [1] 执行成功")
    print("    [2] 动作性失败")
    print("    [3] 环境性失败（雨量联锁）")
    c = input("  >> ").strip()

    ok, recomputed, anchor = st.verify_pointer(pid)
    if not ok:
        print(f"  {RED}[报警] 指纹校验不一致，拒绝使用该经验。{RESET}")
        return
    print(f"  {GREEN}指纹校验通过。{RESET}")

    params = json.loads(p["params"]) if p["params"] else {}

    gok, gkind, gmsg = gateway.gateway_check(
        action=p["action"], action_obj=p["action_obj"], params=params,
        task=task, baseline=BASELINE, whitelist=WHITELIST, ranges=RANGES)

    if not gok:
        if gkind == "self_unsafe":
            p["quarantined"] = 1
            st.save_pointer(p)
            print(f"  {RED}[归因：经验自身不安全]{RESET} {gmsg}")
            print("  → 跳过阈值判定，直接置为隔离。权重未变（仍为"
                  f"{p['weight']}）。")
        else:
            st.append_log("mismatch", {"ptr_id": pid, "msg": gmsg})
            print(f"  {YELLOW}[归因：任务不匹配]{RESET} {gmsg}")
            print("  → 只记审计日志。权重与状态均不变。")
            print("  → 这正是防止「一次构造输入永久隔离正确经验」的那道防线。")
        return

    if c == "1":
        p["weight"] = round(min(W.INIT_W, p["weight"] + W.STEP_UP), 4)
        p["tier"] = W.tier_of(p["weight"])
        p["last_success_ts"] = store_mod.now()
        st.save_pointer(p)
        print(f"  {GREEN}[成功]{RESET} 权重回升至 {p['weight']}（档位 {p['tier']}）")
        return

    if c == "3":
        st.append_log("env_fail", {"ptr_id": pid})
        print(f"  {YELLOW}[归因：环境性失败]{RESET} 雨量联锁 / 设备忙 一类。")
        print(f"  → 不降低权重（仍为 {p['weight']}）。环境噪声不消耗权重预算。")
        return

    p["weight"] = round(p["weight"] * W.STEP_DOWN, 4)
    p["tier"] = W.tier_of(p["weight"])
    if p["weight"] < W.THRESHOLD:
        p["quarantined"] = 1
        st.save_pointer(p)
        print(f"  {RED}[归因：动作性失败]{RESET} 权重降至 {p['weight']}，"
              f"低于阈值 {W.THRESHOLD}，置为隔离。")
    else:
        st.save_pointer(p)
        print(f"  {YELLOW}[归因：动作性失败]{RESET} 权重降至 {p['weight']}"
              f"（档位 {p['tier']}），尚未低于阈值。")

# ---------------- 篡改测试 ----------------

def tamper_test():
    """
    【这一段演示专利第(9)条缺陷的解法】
    直接把数据库里的权重改掉，并且同步重算中层哈希——
    中层这一关骗过去了，但底层留存的锚对不上，篡改照样被发现。
    """
    header("篡改测试：绕过应用层，直接改数据库")

    ptrs = st.list_pointers(include_quarantined=True)
    if not ptrs:
        print("  没有经验可测。")
        return

    pid = ptrs[0]["ptr_id"]
    print(f"  目标经验：{pid}")

    ok_before, _, _ = st.verify_pointer(pid)
    print(f"  篡改前指纹校验：{ok_before}{'' if ok_before else '（已异常）'}")

    # 直接改数据库：把权重改成 0.99
    from canon import canonical, digest
    row = st.get_pointer(pid)
    row["weight"] = 0.99
    body = {k: row[k] for k in store_mod.PTR_FIELDS}
    fake_hash = digest(canonical(body))
    st.conn.execute("UPDATE pointers SET weight=?, ptr_hash=? WHERE ptr_id=?",
                    (0.99, fake_hash, pid))
    st.conn.commit()
    print("  已把权重从原值改为 0.99，并同步重算了中层哈希。")

    ok_after, recomputed, anchor = st.verify_pointer(pid)
    print(f"\n  篡改后指纹校验：{RED}{ok_after}{RESET}")
    print(f"  中层重算：{recomputed[:16]}…")
    print(f"  底层锚　：{str(anchor)[:16]}…")
    print(f"\n  {GREEN}结论：改写者能改中层、能重算中层哈希，"
          f"但改不了仅追加的底层日志。{RESET}")
    print("  这就是「校验材料独立于被校验对象存放」的实际效果。")


# ---------------- 主菜单 ----------------

def main():
    header("智能体经验记忆 · 可信写入与衰减管理（交互演示）")
    print("  本演示包含：大模型提议 → 三重门控 → 执行 → 经验沉淀")
    print("  说明：执行环节为模拟，不接真实执行机构。")

    while True:
        print("\n" + "-" * 62)
        print("  [1] 可信输入（模拟用户正常要求）")
        print("  [2] 外部不可信输入（模拟网页/邮件注入）")
        print("  [3] 查看经验库（含指纹校验状态）")
        print("  [4] 调用一条经验（演示归因三分与权重衰减）")
        print("  [5] 篡改测试（演示哈希锚发现篡改）")
        print("  [0] 退出")
        c = input("  >> ").strip()

        if c == "0":
            print("\n  演示结束。")
            break
        elif c == "1":
            run_once("trusted")
        elif c == "2":
            run_once("untrusted")
        elif c == "3":
            show_memory()
        elif c == "4":
            call_existing()
        elif c == "5":
            tamper_test()
        else:
            print("  输入无效。")


if __name__ == "__main__":
    main()

