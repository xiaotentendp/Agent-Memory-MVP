"""
【这个文件干什么】
在动作执行之前，先过一遍安检。这是"第二道门"（第一道是污点检查）。
"""

# 环境性异常的错误码集合。
# 这些错误说明"外部条件不允许"，不是经验本身有毛病。
ENV_ERROR_CODES = {
    "E_TIMEOUT",          # 超时
    "E_BUSY",             # 设备忙
    "E_RESOURCE",         # 资源占用
    "E_RAIN_INTERLOCK",   # 雨量联锁（下雨不许开窗）
    "E_DEVICE_MAINT",     # 设备维护中
    "E_PRECONDITION",     # 前置条件不满足
}

# 【新增：领域实体同义词字典】
# 用于处理大模型中英文混杂、同义词幻觉的问题
ALIAS_MAP = {
    # 车窗变体
    "window": "车窗",
    "car_window": "车窗",
    "front_window": "车窗",
    "rear_window": "车窗",
    "窗户": "车窗",
    "汽车窗户": "车窗",
    "玻璃": "车窗",
    "车窗玻璃": "车窗",
    
    # 空调变体
    "air_conditioner": "空调",
    "车内": "空调",
    "车厢": "空调",
    "座舱": "空调",
    "驾驶室": "空调",
    "温度": "空调",
    "ac": "空调",
    
    # 车门变体
    "door": "车门",
    "门": "车门",
    "车门锁": "车门"
}

# 领域实体字典：左边是标准实体，右边是各种可能的同义词/近义词
DOMAIN_ALIAS_MAP = {
    "空调": ["车内", "车厢", "座舱", "驾驶室", "温度"],
    "车窗": ["窗户", "玻璃", "车窗玻璃"],
    "车门": ["门", "车门锁"]
}

def normalize_entity(entity_name):
    """将传入的实体名，映射为字典里的标准名。如果没有对应，就返回原词。"""
    if not entity_name:
        return entity_name
    # 遍历字典，看看传入的词是不是某个标准词的同义词
    for standard_name, aliases in DOMAIN_ALIAS_MAP.items():
        if entity_name == standard_name or entity_name in aliases:
            return standard_name
    return entity_name
def gateway_check(action, action_obj, params, task, baseline, whitelist, ranges):
    """
    【返回】(是否通过, 归因类别, 说明)
      归因类别有三种：None（通过）、"self_unsafe"（经验自身不安全）、"task_mismatch"（任务不匹配）
    """
    # 检查一：动作必须在白名单里
    if action not in whitelist:
        return False, "self_unsafe", "动作不在动作白名单内"

    # 检查二：不能违反顶层安全基线
    if baseline.get("moving") and action in baseline.get("forbid_when_moving", []):
        return False, "self_unsafe", "违反顶层安全基线：行驶中禁止该动作"

    # 检查三：参数必须在合法区间
    lo, hi = ranges.get(action, (None, None))
    if lo is not None:
        num = None
        for v in params.values():
            try:
                num = float(v)
                break
            except (TypeError, ValueError):
                continue

        if num is None:
            return False, "self_unsafe", "缺少必需的数值参数"
        if not (lo <= num <= hi):
            return False, "self_unsafe", f"参数超出当前生效区间 [{lo}, {hi}]"

    # 检查四：动作和对象，必须与"当前任务的可信指令"一致
    # 引入实体归一化
    norm_action_obj = normalize_entity(action_obj)
    norm_task_target = normalize_entity(task.get("target"))

    if action != task.get("action") or norm_action_obj != norm_task_target:
        return False, "task_mismatch", f"动作或对象与当前任务不匹配 (输出:{action_obj}, 任务:{task.get('target')})"

    return True, None, "通过"