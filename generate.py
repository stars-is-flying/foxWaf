import json
from pathlib import Path

def ensure_list(obj):
    """保证返回的是列表"""
    if obj is None:
        return []
    if isinstance(obj, list):
        return obj
    return [obj]

def process_class(class_obj, parent_dir):
    """递归处理 main_class 和 sub_class"""
    class_name = class_obj.get("-class_name", "unknown_class")
    class_dir = parent_dir / class_name
    class_dir.mkdir(parents=True, exist_ok=True)

    # 处理规则
    rules = ensure_list(class_obj.get("rule"))
    for rule in rules:
        if not isinstance(rule, dict):
            continue

        match_seg = ensure_list(rule.get("match_seg"))
        judge = []
        for j in match_seg:
            judge.append({
                "position": j.get("match_pos", ""),
                "content": j.get("match_key", ""),
                "rix": j.get("match_value", "")
            })

        rule_file_path = class_dir / f"{rule.get('-rule_id', 'unknown_rule')}.json"
        with open(rule_file_path, "w", encoding="utf-8") as f:
            json.dump({
                "name": rule.get("name", ""),
                "id": rule.get("-rule_id", ""),
                "method": "any",
                "description": rule.get("description", ""),
                "judge": judge
            }, f, ensure_ascii=False, indent=4)

    # 递归处理子类
    sub_classes = ensure_list(class_obj.get("sub_class"))
    for sub in sub_classes:
        if isinstance(sub, dict):
            process_class(sub, class_dir)

# ---------- 主程序 ----------
Path("main_class").mkdir(exist_ok=True)

with open('./rule/r.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

for main in ensure_list(data.get("signature_rules", {}).get("main_class")):
    if isinstance(main, dict):
        process_class(main, Path("main_class"))

print("规则文件生成完成！")
