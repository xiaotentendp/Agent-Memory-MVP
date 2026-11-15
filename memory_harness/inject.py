"""
【这个文件干什么】
当需要参考旧经验时，从这里把经验调出来，拼成一段文字给模型看。
"""

from weights import tier_of

# 用来判断动作之间是否互斥（比如开窗和关窗是对着干的）
# 存的是：动作名 -> (受控的物理量, 方向)
CONTROL = {
    "open_window": ("window", +1),  # 车窗，方向：打开（正）
    "close_window": ("window", -1), # 车窗，方向：关闭（负）
    "reduce_feed": ("feed", -1),    # 进给量，方向：减少
    "increase_feed": ("feed", +1),  # 进给量，方向：增加
    "open_door": ("door", +1),      # 车门，方向：打开
}


def retrieve(store, tag, domain):
    # 1. 从库里找出 主经验、指定的领域、指定的标签
    rows = store.list_pointers(kind="primary", domain=domain, tag=tag, include_quarantined=False)
    
    # 2. 把那些被篡改过（指纹校验失败）的经验踢掉
    rows = [r for r in rows if store.verify_pointer(r["ptr_id"])[0]]
    
    # 3. 按照权重降序排，权重一样按版本号降序，再按成功时间排
    return sorted(rows, key=lambda r: (-r["weight"], -r["version"], r["last_success_ts"] or ""))


def resolve_conflict(ptrs):
    groups, others = {}, []
    
    # 把经验按受控对象分组（比如全都归到 window 组）
    for p in ptrs:
        c = CONTROL.get(p["action"])
        if not c:
            others.append(p) # 不认识的直接留下
            continue
        groups.setdefault(c[0], []).append((c[1], p))

    kept = list(others)
    
    for _, items in groups.items():
        # 如果同一个物理量出现了不同的方向（比如又开窗又关窗），那就是冲突
        if len({d for d, _ in items}) > 1:
            # 【修复】当权重一样时，按版本号(version)、创建时间(created_ts)、编号(ptr_id)降序排
            # reverse=True 保证最新的、或者编号最大的排在前面
            best_item = sorted(
                items, 
                key=lambda x: (x[1]["weight"], x[1]["version"], x[1]["created_ts"], x[1]["ptr_id"]), 
                reverse=True
            )[0]
            kept.append(best_item[1])
        else:
            # 方向一致（比如都是开窗），全留下
            kept.extend(p for _, p in items)
            
    return sorted(kept, key=lambda r: -r["weight"])


def build_injection(pts, limit=3):
    # 把挑好的经验，拼成一段文字，准备塞给大模型看
    lines = []
    # 最多只取 3 条，防止 Prompt 太长
    for p in resolve_conflict(pts)[:limit]:
        # 注意：这里调用 tier_of()，只给“高/中/低”，绝对不暴露权重数字
        lines.append(
            f"【经验】{p['summary']}｜标签：{p['tag']}｜权重档位：{tier_of(p['weight'])}")
    return "\n".join(lines)