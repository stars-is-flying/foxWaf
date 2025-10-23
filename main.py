# Please install OpenAI SDK first: `pip3 install openai`
import os
from openai import OpenAI
import yaml
import json
import random
import string
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed



client = OpenAI(
    api_key="sk-80836e3370a1462eb135df811c341b0c",
    base_url="https://api.deepseek.com")

data = [
    "1 SQL注入",
    "各种 常规 vuln 有 CVE 的 你要是知道 你就生成 哈, 生成越多越好， 然后呢， 要是能统计成常规拦截, 那么尽量写成 常规的规则， 主要是你能不能把它真正看懂",
"2 跨站脚本 XSS",
"3 OS命令注入"
"4 路径遍历",
"5 LDAP注入",
"7 服务器端包含注入 SSI",
"9 HTTP头注入",
"10 不安全的直接对象引用 部分",
"12 使用含有已知漏洞的组件 部分",
"13 敏感信息泄漏 部分",
"远程代码执行， 包括各种编程语言的",
"反序列化，包括java, python, PHP",
"随机， 你自己想一个然后写"
]

rules = []
rules_lock = threading.Lock()
id_counter = 0
id_lock = threading.Lock()

def generate_rule(thread_id):
    global id_counter
    
    with id_lock:
        current_id = id_counter
        id_counter += 1
    
    try:
        client = OpenAI(
            api_key="sk-80836e3370a1462eb135df811c341b0c",
            base_url="https://api.deepseek.com"
        )

        print(f"线程{thread_id}: 处理数据 {current_id % len(data)} - {data[current_id % len(data)]}")
        
        response_rule_generator = client.chat.completions.create(
            model="deepseek-reasoner",
            messages=[
                {"role": "system", "content": """你是一个非常厉害WEB安全专家, 我给你提供一段内容， 你需要帮我生成一个web防火墙wafrule规则, 规则质量越高越好， 
                id: "000001"
        method: any
        description: Upload Webshell Attack
        relation: or
        judge:
        - position: request_header
            content: multipart
            rix: multipart
        - position: request_body
            content: content-disposition,filename
            rix: \bcontent-disposition:.*?\bfilename\s*=[^\n]*?\.(?:as|php|jsp|cer|cdx)
        - position: request_body
            content: $_post
            rix: \$_post 
            这是 我的一个规则简单示例哈， 然后呢 "id" 你可以生成 一个 md5 来保存即可， method 表示 请求 方法， 包括 any, GET,POST,PUT,MOVE,DELETE 等 any 表示所有的 请求类型 description 表示规则描述， relation 表示 多条判断条件之间的关系， and, or 知道吧 or 的时候你可以写很多条同类型规则 都可以 and 表示 所有都满足才算 postion  表示 检测的位置 有三个 uri,request_header, request_body uri 是 整个 url 部分 比如 /data?data=123&a=1 这种 其他两个我不用说了你应该也懂  ， content 表示 关键字 必须要有关键字不能只有 正则表达式， 不然影响 rule 检测 效率， rix 表示 正则， 中了 content 和 正则 才算 命中， 我有几点要求 第一 写的时候 必须要考虑性能， 不能写的很随便， 并且 同类型的 可以利用 or 关系 添加到同一个 规则里面， 然后 误拦率要少， 知道吗， 所以确认 100% 攻击才要写
            只需返回一个上面为模板的 json 数据就行 然后 "id" 你先空着， 这个id 我自己生成， 切记 只需要 返回 json 数据, 不要返回任何额外的内容, 每次生成， 说了 除了 json 以为内容 不要给我 即便 ``` ```json 也不要添加， 这一点很重要， 使用 request_body 务必要谨慎哈， 
            3. 硬性要求：
       - 每个judge条目必须包含content关键字和rix正则
       - 优先使用or关系整合同类规则
       - request_body规则必须精确，避免误拦
       - 正则表达式必须经过优化，确保高性能
       - 只针对确认的100%攻击特征编写规则

    4. 输出要求：
       -  rule 一定要有 description 并且是英文的， 不能有空格， 可以用 _ 隔开单词
       - 只返回纯JSON格式
       - 禁止包含任何其他文本、注释或markdown标记
       - 禁止使用```json或```包装， 再次说一遍 不要反悔 ```json 这种内容
                """},
                {"role": "user", "content": f"{data[current_id % len(data)]}"},
            ],
            stream=False
        )
        
        print(f"线程{thread_id}: 规则生成完毕")
        print(response_rule_generator.choices[0].message.content)

        response_rule_evalator = client.chat.completions.create(
            model="deepseek-reasoner",
            messages=[
                {"role": "system", "content": """你是一个非常厉害WEB安全专家, 我会给你提供一段 json 形式的 waf rule 你需要帮我评估 这些规则 是否可行， 你很重要 你要是误判啦， 那么这些正则很有可能会误拦用户的请求
                你的工作室 查看 规则， 需要改进的地方你需要改进， 需要去掉的地方你需要去掉， 甚至是删掉哈， 优化后的正则你在给我返回， 注重注意 request_body 的规则 因为 这里面 很有可能会产生很多种情况容易误拦， 最后切记 只需要返回， json 内容， 其他什么内容
                也不用添加， 只需要返回json 哈， 说了 除了 json 以为内容 不要给我 即便 ``` ```json 也不要添加， 这一点很重要
                1. 严格审查提供的WAF规则：
       - 检查规则是否存在误拦风险
       - 优化正则表达式性能
       - 特别审查request_body规则的精确性
       - 删除不必要或高风险的条件

    2. 硬性要求：
       - 必须修复所有识别到的问题
       - 优化后的规则必须保持高检测率和低误报率
       - 正则表达式必须精确匹配攻击特征
                """},
                {"role": "user", "content": f"{response_rule_generator.choices[0].message.content}"},
            ],
            stream=False
        )

        rule_content = response_rule_evalator.choices[0].message.content
        
        # 处理规则
        if rule_content[0] == '[':
            rule = json.loads(rule_content)
            for i in range(len(rule)):
                with rules_lock:
                    for judge_elem in rule[i]["judge"][:]:  # 使用切片创建副本避免修改时迭代
                        if judge_elem in rules:
                            print(f"线程{thread_id}: 检测到重复")
                            rule[i]["judge"].remove(judge_elem)
                
                if len(rule[i]["judge"]) == 0:
                    print(f"线程{thread_id}: 规则{i}结果已经为空,跳过")
                    continue
                    
                with rules_lock:
                    rules.append(rule[i]["judge"])
                
                random_number = ''.join(random.choices(string.digits, k=16))
                rule[i]["id"] = random_number
                
                yaml_data = yaml.dump(rule[i], default_flow_style=False, allow_unicode=True, sort_keys=False)
                filename = f"./rule/{current_id % 13}_{random_number}.yaml"
                with open(filename, "w") as file:
                    file.write(yaml_data)
                print(f"线程{thread_id}: 规则写入完毕 - {filename}")
        else:
            rule = json.loads(rule_content)
            
            with rules_lock:
                for judge_elem in rule["judge"][:]:  # 使用切片创建副本
                    if judge_elem in rules:
                        print(f"线程{thread_id}: 检测到重复")
                        rule["judge"].remove(judge_elem)
            
            if len(rule["judge"]) == 0:
                print(f"线程{thread_id}: 结果已经为空,跳过")
                return
            
            with rules_lock:
                rules.append(rule["judge"])
            
            random_number = ''.join(random.choices(string.digits, k=16))
            rule["id"] = random_number
            
            yaml_data = yaml.dump(rule, default_flow_style=False, allow_unicode=True, sort_keys=False)
            yaml_data = yaml_data.replace('-', '\n\n-')
            filename = f"./rule/{current_id % 13}_{random_number}.yaml"
            with open(filename, "w") as file:
                file.write(yaml_data)
            print(f"线程{thread_id}: 规则写入完毕 - {filename}")
            
    except Exception as e:
        print(f"线程{thread_id}: 发生错误 - {str(e)}")

def main():
    # 创建规则目录（如果不存在）
    os.makedirs("./rule", exist_ok=True)
    
    # 使用线程池执行器，开启10个线程
    with ThreadPoolExecutor(max_workers=50) as executor:
        # 提交任务
        futures = [executor.submit(generate_rule, i) for i in range(50)]
        
        # 等待所有任务完成
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"任务执行出错: {e}")

if __name__ == "__main__":
    while True:
        main()