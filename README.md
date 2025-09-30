# WAF 反向代理安全网关

## 项目概述

这是一个基于 Go 语言开发的高性能 Web 应用防火墙（WAF）和反向代理系统，集成了安全防护、访问控制、缓存加速和站点管理等功能。

## 功能特性

### 🔒 安全防护
- **智能 WAF 防护**：基于规则引擎的 Web 攻击检测和拦截
- **多维度检测**：支持 URI、请求头、请求体、参数值、表单值等多位置检测
- **编码识别**：自动识别和解码 Base64、URL 编码的攻击载荷
- **实时拦截**：对 SQL 注入、XSS、路径遍历等攻击进行实时阻断

### 🌐 反向代理
- **多站点支持**：支持基于域名的多站点反向代理
- **HTTPS 支持**：自动生成和管理 SSL/TLS 证书
- **负载均衡**：内置连接池和超时控制
- **协议转换**：支持 HTTP/HTTPS 协议转换

### 🛡️ 访问控制 (ACL)
- **灵活规则**：支持全局和基于域名的访问控制规则
- **多种匹配**：IP 地址、用户代理、Referer、路径等多种匹配条件
- **实时生效**：规则添加后立即生效，无需重启服务

### ⚡ 性能优化
- **静态缓存**：智能静态文件缓存，大幅提升访问速度
- **内存优化**：高效的内存管理和并发控制
- **连接复用**：HTTP 连接池和 Keep-Alive 支持

### 🛠️ 管理功能
- **Web 管理界面**：基于 Gin 框架的现代化管理界面
- **JWT 认证**：安全的用户认证和会话管理
- **实时统计**：请求量、拦截率、缓存命中率等实时监控
- **站点管理**：动态添加和管理反向代理站点

## 系统架构

```
客户端请求
    ↓
ACL 访问控制检查
    ↓
WAF 安全检测
    ↓
静态缓存检查
    ↓
反向代理转发
    ↓
目标服务器
```

## 快速开始

### 安装步骤

1. **克隆项目**
```bash
git clone git@github.com:stars-is-flying/wafMax.git
cd wafMax
```

2. **配置数据库**
```sql
CREATE DATABASE waf_proxy;
```

3. **修改配置文件**
创建 `conf.json` 文件：
```json
{
  "server": {
    "addr": "0.0.0.0",
    "port": 8080
  },
  "database": {
    "host": "localhost",
    "port": 3306,
    "user": "root",
    "password": "your_password",
    "dbname": "waf_proxy"
  },
  "isWriteDbAuto": true,
  "secureentry": "admin"
}
```

4. **准备规则文件**
在 `rule_updated/` 目录下放置 WAF 规则文件（JSON 格式）。

5. **准备静态文件**
在 `static/` 目录下放置管理界面所需的 HTML 文件：
- `login.html` - 登录页面
- `loginError.html` - 登录错误页面  
- `panle.html` - 管理面板
- `404.html` - 404 页面
- `waf/` - WAF 拦截页面

6. **运行项目**
```bash
go mod tidy
go run main.go
```

### 默认账户

启动后控制台会显示默认的管理员账户和密码：
```
------------------------账户信息---------------------------
账户密码为: fox:随机密码
-----------------------------------------------------------
```

访问 `http://your-server:8080/admin` 使用默认账户登录管理界面。

## 配置说明

### 主配置文件 (conf.json)

```json
{
  "server": {
    "addr": "监听地址",
    "port": 监听端口
  },
  "database": {
    "host": "数据库主机",
    "port": 数据库端口,
    "user": "数据库用户", 
    "password": "数据库密码",
    "dbname": "数据库名"
  },
  "isWriteDbAuto": "是否自动写入攻击日志",
  "secureentry": "管理界面入口路径"
}
```

### WAF 规则配置

规则文件放置在 `rule_updated/` 目录下，支持 JSON 格式：

```json
{
  "name": "SQL注入检测",
  "description": "检测SQL注入攻击",
  "id": "sql-injection-001",
  "method": "any",
  "relation": "or",
  "judge": [
    {
      "position": "uri",
      "content": "union select",
      "rix": "(?i)union\\\\s+select"
    }
  ]
}
```

### ACL 规则类型

- **type**: `global`（全局）或 `host`（域名特定）
- **rule_type**: `ip`, `user_agent`, `referer`, `path`, `country`
- **action**: `allow`（允许）或 `block`（阻止）



## 部署说明

### 生产环境部署

1. **编译项目**
```bash
go build -o wafMax waf.go
```

2. **使用 systemd 管理服务**
创建 `/etc/systemd/system/waf-proxy.service`：
```ini
[Unit]
Description=WAF Reverse Proxy
After=network.target

[Service]
Type=simple
User=www
WorkingDirectory=/path/to/waf-proxy
ExecStart=/path/to/waf-proxy/waf-proxy
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

3. **启动服务**
```bash
systemctl daemon-reload
systemctl enable waf-proxy
systemctl start waf-proxy
```

### Docker 部署

```dockerfile
FROM golang:1.19-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o waf-proxy main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/waf-proxy .
COPY static ./static
COPY rule_updated ./rule_updated
COPY conf.json .
EXPOSE 80 443 8080
CMD ["./waf-proxy"]
```

## 性能调优

### 缓存配置
```go
staticCacheConfig = StaticCacheConfig{
    Enable:          true,
    CacheDir:        "./static_cache", 
    MaxCacheSize:    100 * 1024 * 1024, // 100MB
    DefaultExpire:   24 * time.Hour,
    CleanupInterval: 1 * time.Hour,
}
```

### 数据库连接池
```go
db.SetMaxOpenConns(20)
db.SetMaxIdleConns(10)
db.SetConnMaxLifetime(time.Minute * 5)
```

## 监控和维护


### 性能监控
访问管理界面的统计页面查看：
- 总请求数
- 拦截请求数  
- 缓存命中率
- 规则数量
- 站点数量

### 数据库维护
定期清理攻击日志：
```sql
DELETE FROM attacks WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY);
```

## 故障排除

### 常见问题

1. **证书加载失败**
   - 检查证书文件格式
   - 验证私钥匹配
   - 检查文件权限

2. **数据库连接失败**
   - 验证数据库配置
   - 检查网络连通性
   - 确认用户权限

3. **规则不生效**
   - 检查规则文件格式
   - 验证正则表达式
   - 查看错误日志



## 安全建议

1. **定期更新规则**：及时更新 WAF 规则以应对新威胁
2. **监控日志**：定期检查攻击日志和安全事件
3. **权限控制**：严格管理管理员账户权限
4. **网络隔离**：将 WAF 部署在 DMZ 区域
5. **证书管理**：定期更新 SSL/TLS 证书

## 许可证

[在此添加项目许可证信息]

## 贡献指南

欢迎提交 Issue 和 Pull Request 来改进这个项目。

## 联系方式

- 邮箱：[211310412@mail.dhu.edu.cn]

---

**注意**: 这是一个用于学习和研究目的的项目，在生产环境中使用前请进行充分测试和安全评估
