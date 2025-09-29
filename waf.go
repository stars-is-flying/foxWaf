package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
	"log"
	"crypto/tls"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"math"
	"io/ioutil"
	"crypto/rand"
	"unicode/utf8"
	"github.com/golang-jwt/jwt/v5"
	
	

	_ "github.com/go-sql-driver/mysql"
	"github.com/gin-gonic/gin"
	"github.com/fatih/color"
)

import (
    stdlog "log" // 使用别名
)

// ------------------- 配置 -------------------
type ServerConfig struct {
	Addr string `json:"addr"`
	Port int    `json:"port"`
}

type DatabaseConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	DBName   string `json:"dbname"`
}

type Config struct {
	Server        ServerConfig   `json:"server"`
	Database      DatabaseConfig `json:"database"`
	IsWriteDbAuto bool           `json:"isWriteDbAuto"`
	Secure        string         `json:"secureentry"`
}

var cfg Config // 全局配置

// ------------------- 规则 -------------------
type Judge struct {
	Position string `json:"position"`
	Content  string `json:"content"`
	Rix      string `json:"rix"`

	regex *regexp.Regexp
}

type Rule struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	ID          string  `json:"id"`
	Method      string  `json:"method"`
	Judges      []Judge `json:"judge"`
}

var RULES map[string][]Rule

// ------------------- 攻击记录 -------------------
type AttackLog struct {
	Method       string `json:"method"`
	URL          string `json:"url"`
	Headers      string `json:"headers"`
	Body         string `json:"body"`
	RuleName     string `json:"rule_name"`
	RuleID       string `json:"rule_id"`
	MatchedValue string `json:"matched_value"`
}


//站点
type Site struct {
    ID          int
    Name        string
    Domain      string
    TargetURL   string
    EnableHTTPS bool
	CERTID      sql.NullInt64
    Status      int
    CreatedAt   string // 可以用 time.Time
    UpdatedAt   string // 可以用 time.Time
}

//管理员信息
var username string
var password string
var jsonTokenKey []byte

var sites []Site
var certificateMap = map[string]tls.Certificate{}


var attackChan = make(chan AttackLog, 1000)
var workerCount = 5
var db *sql.DB

// ------------------- 内存统计 -------------------
var totalRequests uint64
var totalBlocked uint64


//---------base64Decode------------------
var maxDepth = 2
var isActivateBase64 = true


//---------urlDecode-----------------------

var maxUrlDepth = 2
var isActivateUrlDecode = true


// 百分比（0~100）控制要用多少规则
var RuleMatchRate int = 100 // 默认 100% 使用





// ------------------- 添加站点接口 -------------------
type AddSiteRequest struct {
    Name        string `json:"name" binding:"required"`
    Domain      string `json:"domain" binding:"required"`
    TargetURL   string `json:"target_url" binding:"required"`
    EnableHTTPS bool   `json:"enable_https"`
    CertName    string `json:"cert_name"` // 可选，自动生成自签名
}

// addSiteHandler 添加站点并热更新内存
func addSiteHandler(c *gin.Context) {
    var req AddSiteRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    var certID interface{} = nil
    if req.EnableHTTPS {
        // 生成自签名证书并存数据库
        certPEM, keyPEM, err := generateSelfSignedCert(req.Domain)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("生成证书失败: %v", err)})
            return
        }
        insertCert := `INSERT INTO certificates (name, cert_text, key_text) VALUES (?, ?, ?)`
        result, err := db.Exec(insertCert, req.CertName, certPEM, keyPEM)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("写入证书失败: %v", err)})
            return
        }
        id, _ := result.LastInsertId()
        certID = id

        // 热加载证书到内存
        cert, err := tls.X509KeyPair(certPEM, keyPEM)
        if err != nil {
            log.Printf("加载证书失败: %v", err)
        } else {
            certificateMap[req.Domain] = cert
            log.Printf("新证书已加载: %s", req.Domain)
        }
    }

    // 插入站点数据库
    insertSite := `INSERT INTO sites (name, domain, target_url, enable_https, cert_id, status) VALUES (?, ?, ?, ?, ?, ?)`
    _, err := db.Exec(insertSite, req.Name, req.Domain, req.TargetURL, boolToInt(req.EnableHTTPS), certID, 1)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("写入站点失败: %v", err)})
        return
    }

    // 热更新内存 sites 列表
    newSite := Site{
        Name:        req.Name,
        Domain:      req.Domain,
        TargetURL:   req.TargetURL,
        EnableHTTPS: req.EnableHTTPS,
        Status:      1,
    }
    sites = append(sites, newSite)

    c.JSON(http.StatusOK, gin.H{"message": "站点添加成功"})
}

func boolToInt(b bool) int {
    if b {
        return 1
    }
    return 0
}

// JWT 生成函数
func generateToken(user string) (string, error) {
	// 设置过期时间为 24 小时
	expirationTime := time.Now().Add(24 * time.Hour)

	claims := jwt.MapClaims{
		"username": user,
		"exp":      expirationTime.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jsonTokenKey)
}

// 登录处理
func loginHandler(c *gin.Context) {
	formUsername := c.PostForm("username")
	formPassword := c.PostForm("password")

	if formUsername != username || formPassword != password {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"error": "用户名或密码错误",
		})
		return
	}

	// 生成 JWT
	tokenString, err := generateToken(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成 token 失败"})
		return
	}

	// 设置 Cookie，24 小时有效
	c.SetCookie("auth_token", tokenString, 3600*24, "/", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"message": "登录成功",
		"token":   tokenString,
	})
}


func StartGinAPI() {
	gin.SetMode(gin.ReleaseMode)
    r := gin.Default()


	//safe login
	login, _ := ioutil.ReadFile("./static/login.html")
	//waf

	//添加站点
    r.POST("/api/site/add", addSiteHandler)
	//登录验证
	r.POST("/login", loginHandler)

	//登录页面
	r.GET(cfg.Secure, func(ctx *gin.Context) {
    ctx.Header("Content-Type", "text/html; charset=utf-8")
    ctx.String(http.StatusOK, string(login))
	})


    log.Println("Gin API 启动在 :8080")
    if err := r.Run(":8080"); err != nil {
        log.Fatalf("Gin 启动失败: %v", err)
    }
}

// 定义三个变量，用于存储 HTML 内容


// wafDir 是 HTML 文件存放目录
var wafDir = "./static/waf"

func loadWAFPage(filename string) string {
    path := filepath.Join(wafDir, filename)
    content, err := ioutil.ReadFile(path)
    if err != nil {
        log.Fatalf("加载文件 %s 失败: %v", filename, err)
    }
    return string(content)
}

// 初始化函数，程序启动时加载 HTML 文件
var interceptPage string
var NotFoundPage string
var proxyErrorPage string


func readWafHtml() {
    interceptPage = loadWAFPage("intercept.html")
    NotFoundPage = loadWAFPage("notfound.html")
    proxyErrorPage = loadWAFPage("proxy_error.html")
}


func statsPrinter() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		tr := atomic.LoadUint64(&totalRequests)
		tb := atomic.LoadUint64(&totalBlocked)
		fmt.Printf("\r总请求数: %d, 总拦截数: %d", tr, tb)
	}
}


// ------------------- 工具函数 -------------------
func MultiDecode(raw string) string {
	for i := 0; i < maxUrlDepth; i++ {
		decoded, err := url.QueryUnescape(raw)
		if err != nil || decoded == raw {
			break
		}
		raw = decoded
	}
	return raw
}

func GetBodyString(r *http.Request) (string, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return "", err
	}
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	return string(bodyBytes), nil
}

func generateRandomPassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	password := make([]byte, length)
	charsetLen := byte(len(charset))

	for i := 0; i < length; i++ {
		b := make([]byte, 1)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		password[i] = charset[b[0]%charsetLen]
	}

	return string(password), nil
}

func match(data string, judge Judge) string {
	if judge.Rix != "" && judge.regex != nil {
		if loc := judge.regex.FindStringIndex(data); loc != nil {
			return data[loc[0]:loc[1]]
		}
	} else if judge.Content != "" && strings.Contains(data, judge.Content) {
		return judge.Content
	}
	return ""
}

func GetParamValues(req *http.Request) string {
	params := req.URL.Query()
	var sb strings.Builder
	for k, vs := range params {
		for _, v := range vs {
			sb.WriteString(fmt.Sprintf("%s=%s\n", k, v))
		}
	}
	return sb.String()
}

func GetFormValues(req *http.Request) string {
	if req.Method != http.MethodPost {
		return ""
	}
	req.ParseForm()
	var sb strings.Builder
	for k, vs := range req.PostForm {
		for _, v := range vs {
			sb.WriteString(fmt.Sprintf("%s=%s\n", k, v))
		}
	}
	return sb.String()
}





// 如果是合法 base64 就解码，否则原样返回
func tryBase64Decode(s string) string {

    // 限制：单次解码后替换长度不得超过此值（字节）
    const maxDecodedSize = 10 * 1024 * 1024 // 10MB，可按需调整

    for depth := 0; depth < maxDepth; depth++ {
        // 找到所有匹配的开始/结束索引
        idxs := base64Regex.FindAllStringIndex(s, -1)
        if len(idxs) == 0 {
            break
        }

        changed := false
        // 从后向前替换，避免索引偏移问题
        for i := len(idxs) - 1; i >= 0; i-- {
            start, end := idxs[i][0], idxs[i][1]
            if start >= end || start < 0 || end > len(s) {
                continue
            }
            match := s[start:end]

            // 尝试解码
            decodedBytes, err := base64.StdEncoding.DecodeString(match)
            if err != nil {
                // 解码失败就跳过（保留原文）
                continue
            }

            // 防护：解码后不要太大
            if len(decodedBytes) > maxDecodedSize {
                continue
            }

            // 仅在解码后是合法 UTF-8 的情况下替换（避免把二进制填入文本）
            if !utf8.Valid(decodedBytes) {
                // 若确实想替换二进制也可去掉此判断
                continue
            }

            // 替换该片段
            s = s[:start] + string(decodedBytes) + s[end:]
            changed = true
        }

        if !changed {
            break
        }
        // 如果 changed 为真，下一轮会再次在新的字符串中查找（支持嵌套 Base64）
    }

    return s
}

var base64Regex *regexp.Regexp

func readBase64() {
    // ^ 和 $ 限制必须整个字符串都是 base64
    base64Regex = regexp.MustCompile("(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
}


// 工具：输出 URL 编码和 Base64 编码后的请求
func debugPrintRequest(rawURL, head, body string) {
    println(rawURL)
	println(head)
	println(body)
}


// ------------------- 攻击检测 -------------------
func isAttack(req *http.Request) (bool, *AttackLog) {
    

    // headers
    var sb strings.Builder
    for key, values := range req.Header {
        for _, v := range values {
            sb.WriteString(fmt.Sprintf("%s: %s\n", key, v))
        }
    }
    
    

    // body
    isBodyNull := req.ContentLength == 0
    body, err := GetBodyString(req)
    if err != nil {
        body = ""
    }



	rawURL := req.URL.String()
	head := sb.String()
	paramValues := GetParamValues(req)
	formValues := GetFormValues(req)
	if isActivateUrlDecode {
		rawURL = MultiDecode(rawURL)
		head = MultiDecode(head)
		body = MultiDecode(body)
		paramValues = MultiDecode(paramValues)
		formValues = MultiDecode(formValues)
	}
    

	if isActivateBase64 {
		rawURL = tryBase64Decode(rawURL)
		head = tryBase64Decode(head)
    	body = tryBase64Decode(body)
		paramValues = tryBase64Decode(paramValues)
		formValues = tryBase64Decode(formValues)
	}

	debugPrintRequest(rawURL, head, body)

    var rules []Rule
	if methodRules, ok := RULES[req.Method]; ok {
		rules = append(rules, methodRules...)
	}
	if anyRules, ok := RULES["any"]; ok {
		rules = append(rules, anyRules...)
	}

	if RuleMatchRate < 100 && RuleMatchRate > 0 && len(rules) > 0 {
		// 算要用多少条
		limit := len(rules) * RuleMatchRate / 100
		if limit < 1 {
			limit = 1
		}
		rules = rules[:limit]
	}


    for _, rule := range rules {
        allMatched := true
        matchedValues := make([]string, 0, len(rule.Judges))

        for _, judge := range rule.Judges {
            var target string
            switch judge.Position {
            case "uri":
                target = rawURL
            case "request_header":
                target = head
            case "request_body":
                if isBodyNull {
                    allMatched = false
                    continue
                }
                target = body
            case "parameter_value":
                target = paramValues
            case "form_values":
                target = formValues
            default:
                allMatched = false
                continue
            }

            matchedStr := match(target, judge)
            if matchedStr == "" {
                allMatched = false
                break
            }
            matchedValues = append(matchedValues, matchedStr)
        }

        if allMatched {
            log := AttackLog{
                Method:       req.Method,
                URL:          rawURL,
                Headers:      head,
                Body:         body,
                RuleName:     rule.Name,
                RuleID:       rule.ID,
                MatchedValue: strings.Join(matchedValues, "; "),
            }
            return true, &log
        }
    }

    return false, nil
}



// ------------------- Worker -------------------
func attackWorker() {
	for log := range attackChan {
		// 使用 Base64 编码存储，防止 MySQL 非 UTF-8 报错
		urlB64 := base64.StdEncoding.EncodeToString([]byte(log.URL))
		bodyB64 := base64.StdEncoding.EncodeToString([]byte(log.Body))
		headersB64 := base64.StdEncoding.EncodeToString([]byte(log.Headers))

		query := `
			INSERT INTO attacks (method, url, headers, body, rule_name, rule_id, matched_value)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`
		_, err := db.Exec(query,
			log.Method, urlB64, headersB64, bodyB64,
			log.RuleName, log.RuleID, log.MatchedValue)
		if err != nil {
			fmt.Printf("写入攻击数据库失败: %v\n", err)
		}
	}
}



func handler(w http.ResponseWriter, req *http.Request) {
    atomic.AddUint64(&totalRequests, 1)


	// 查找目标站点
    host := req.Host
    var targetURL string
    var enableHTTPS bool

    for _, site := range sites {
        if strings.EqualFold(site.Domain, host) && site.Status == 1 {
            targetURL = site.TargetURL
            enableHTTPS = site.EnableHTTPS
            break
        }
    }

    if targetURL == "" {
        w.WriteHeader(http.StatusNotFound)
        w.Write([]byte(NotFoundPage))
        return
    }
	

    // 先检测是否攻击
	attacked, log := isAttack(req)
	if attacked {
		atomic.AddUint64(&totalBlocked, 1) // 增加总拦截数

		if cfg.IsWriteDbAuto {
			attackChan <- *log
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(interceptPage))
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(log)
		}
		return
	}

    // // 查找目标站点
    // host := req.Host
    // var targetURL string
    // var enableHTTPS bool

    // for _, site := range sites {
    //     if strings.EqualFold(site.Domain, host) && site.Status == 1 {
    //         targetURL = site.TargetURL
    //         enableHTTPS = site.EnableHTTPS
    //         break
    //     }
    // }

    // if targetURL == "" {
    //     w.WriteHeader(http.StatusNotFound)
    //     w.Write([]byte(NotFoundPage))
    //     return
    // }

    // 构造代理请求
    proxyReq, err := http.NewRequest(req.Method, targetURL+req.RequestURI, req.Body)
    if err != nil {
        stdlog.Printf("创建反向代理请求失败: %v", err)
        w.WriteHeader(http.StatusBadGateway)
        w.Write([]byte(proxyErrorPage))
        return
    }

    // 设置重要属性
    proxyReq.Host = req.Host

    // 拷贝请求头（优化版）
    for k, v := range req.Header {
        // 跳过一些需要特殊处理的头部
        if k == "Accept-Encoding" {
            continue
        }
        proxyReq.Header[k] = v
    }

    // 配置传输层
    transport := &http.Transport{
        MaxIdleConns:        100,
        IdleConnTimeout:     90 * time.Second,
        TLSHandshakeTimeout: 10 * time.Second,
    }

    if enableHTTPS {
        transport.TLSClientConfig = &tls.Config{
            InsecureSkipVerify: true,
        }
    }

    client := &http.Client{
        Transport: transport,
        Timeout:   30 * time.Second,
    }

    // 发送请求
    resp, err := client.Do(proxyReq)
    if err != nil {
        stdlog.Printf("请求目标站点失败: %v", err)
        w.WriteHeader(http.StatusBadGateway)
        w.Write([]byte(proxyErrorPage))
        return
    }
    defer func() {
        io.Copy(io.Discard, resp.Body)
        resp.Body.Close()
    }()

    // 拷贝响应头
    for k, v := range resp.Header {
        w.Header()[k] = v
    }

    // 设置状态码并拷贝响应体
    w.WriteHeader(resp.StatusCode)
    _, err = io.Copy(w, resp.Body)
    if err != nil {
        stdlog.Printf("拷贝响应体失败: %v", err)
    }
}

// ------------------- 规则加载 -------------------
func readRule() {
	RULES = make(map[string][]Rule)
	ruleDir := "./rule_updated"

	filepath.WalkDir(ruleDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		if filepath.Ext(path) != ".json" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Printf("读取文件失败: %s, 错误: %v\n", path, err)
			return nil
		}

		if strings.HasPrefix(string(data), "[") {
			var rules []Rule
			if err := json.Unmarshal(data, &rules); err != nil {
				fmt.Printf("解析 JSON 数组失败: %s, 错误: %v\n", path, err)
				return nil
			}
			for _, r := range rules {
				for i := range r.Judges {
					if r.Judges[i].Rix != "" {
						r.Judges[i].regex, _ = regexp.Compile(r.Judges[i].Rix)
					}
				}
				RULES[r.Method] = append(RULES[r.Method], r)
			}
		} else {
			var r Rule
			if err := json.Unmarshal(data, &r); err != nil {
				fmt.Printf("解析 JSON 失败: %s, 错误: %v\n", path, err)
				return nil
			}
			for i := range r.Judges {
				if r.Judges[i].Rix != "" {
					r.Judges[i].regex, _ = regexp.Compile(r.Judges[i].Rix)
				}
			}
			RULES[r.Method] = append(RULES[r.Method], r)
		}

		return nil
	})

	total := 0
	for _, rules := range RULES {
		total += len(rules)
	}
    
	fmt.Printf("所有规则加载完成！方法数: %d，总规则数: %d\n", len(RULES), total)
}

// ------------------- 数据库 -------------------
func initDb() {
	if !cfg.IsWriteDbAuto {
		fmt.Println("isWriteDbAuto=false，跳过数据库初始化")
		return
	}

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.Database.User, cfg.Database.Password, cfg.Database.Host, cfg.Database.Port, cfg.Database.DBName,
	)
	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		panic(fmt.Errorf("连接 MySQL 失败: %v", err))
	}

	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(time.Minute * 5)

	if err := db.Ping(); err != nil {
		panic(fmt.Errorf("Ping 数据库失败: %v", err))
	}

	_, _ = db.Exec("DROP TABLE IF EXISTS attacks;")
	_, _ = db.Exec("DROP TABLE IF EXISTS sites;")
	_, _ = db.Exec("DROP TABLE IF EXISTS certificates;")

	createTable := `
	CREATE TABLE attacks (
		id INT AUTO_INCREMENT PRIMARY KEY,
		method VARCHAR(10),
		url TEXT,
		headers TEXT,
		body LONGTEXT,
		rule_name TEXT,
		rule_id TEXT,
		matched_value TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err := db.Exec(createTable); err != nil {
		panic(fmt.Errorf("建表失败: %v", err))
	}

	createCertTable := `
	CREATE TABLE IF NOT EXISTS certificates (
		id INT AUTO_INCREMENT PRIMARY KEY,
		name VARCHAR(100) NOT NULL COMMENT '证书名称/备注',
		cert_text TEXT NOT NULL COMMENT '证书内容(PEM)',
		key_text  TEXT NOT NULL COMMENT '私钥内容(PEM)',
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '上传时间'
	);`
	if _, err := db.Exec(createCertTable); err != nil {
		panic(fmt.Errorf("建表 certificates 失败: %v", err))
	}

	createTable1 := `
	CREATE TABLE IF NOT EXISTS sites (
		id INT AUTO_INCREMENT PRIMARY KEY,
		name VARCHAR(100) NOT NULL COMMENT '站点名称',
		domain VARCHAR(255) NOT NULL UNIQUE COMMENT '对外访问的域名',
		target_url VARCHAR(255) NOT NULL COMMENT '反向代理目标URL',
		enable_https TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否启用HTTPS (0=否 1=是)',
		cert_id INT DEFAULT NULL COMMENT '关联的证书ID',
		status TINYINT(1) NOT NULL DEFAULT 1 COMMENT '状态 (1=启用 0=禁用)',
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间'
	);`

	if _, err := db.Exec(createTable1); err != nil {
		panic(fmt.Errorf("建表失败: %v", err))
	}

	// 生成测试证书并插入数据库
	certID, err := generateAndInsertTestCertificate()
	if err != nil {
		panic(fmt.Errorf("生成测试证书失败: %v", err))
	}

	// 插入启用 HTTPS 的测试站点
	insertSite := `INSERT INTO sites (name, domain, target_url, enable_https, cert_id, status)
	VALUES (?, ?, ?, ?, ?, ?)`
	_, err = db.Exec(insertSite, "测试HTTPS站点", "kabubu.com", "http://127.0.0.1:8888", 1, certID, 1)
	if err != nil {
		panic(fmt.Errorf("插入站点失败: %v", err))
	}

	// 再插入一个 HTTP 站点作为对比
	_, err = db.Exec(insertSite, "测试HTTP站点", "http.kabubu.com", "http://127.0.0.1:8889", 0, nil, 1)
	if err != nil {
		panic(fmt.Errorf("插入HTTP站点失败: %v", err))
	}

	fmt.Println("测试站点 kabubu.com (HTTPS) 和 http.kabubu.com (HTTP) 已添加")

	// 从数据库加载站点配置
	rows, err := db.Query("SELECT id, name, domain, target_url, enable_https, cert_id, status, created_at, updated_at FROM sites")
	if err != nil {
		panic(fmt.Errorf("查询失败: %v", err))
	}
	defer rows.Close()

	for rows.Next() {
		var s Site
		if err := rows.Scan(&s.ID, &s.Name, &s.Domain, &s.TargetURL, &s.EnableHTTPS, &s.CERTID, &s.Status, &s.CreatedAt, &s.UpdatedAt); err != nil {
			panic(fmt.Errorf("读取失败: %v", err))
		}
		sites = append(sites, s)
	}

	if err := rows.Err(); err != nil {
		panic(fmt.Errorf("迭代失败: %v", err))
	}

	// 初始化证书映射
	if err := initCertificatesFromDB(); err != nil {
		panic(fmt.Errorf("初始化证书失败: %v", err))
	}

	// 现在 sites 变量里就是数据库的内容
	fmt.Printf("读取到 %d 条站点记录\n", len(sites))
	fmt.Printf("加载了 %d 个证书\n", len(certificateMap))

	for i := 0; i < workerCount; i++ {
		go attackWorker()
	}

	fmt.Println("MySQL 已连接，Worker 已启动，数据库已重置")
}

// 从数据库加载证书
func initCertificatesFromDB() error {
	// 查询所有启用了 HTTPS 并且有关联证书的站点
	query := `
		SELECT s.domain, c.cert_text, c.key_text 
		FROM sites s 
		JOIN certificates c ON s.cert_id = c.id 
		WHERE s.enable_https = 1 AND s.status = 1
	`

	rows, err := db.Query(query)
	if err != nil {
		return fmt.Errorf("查询证书失败: %v", err)
	}
	defer rows.Close()

	certificateCount := 0
	for rows.Next() {
		var domain, certText, keyText string
		if err := rows.Scan(&domain, &certText, &keyText); err != nil {
			log.Printf("读取证书数据失败: %v", err)
			continue
		}

		// 从文本加载证书
		cert, err := tls.X509KeyPair([]byte(certText), []byte(keyText))
		if err != nil {
			log.Printf("加载证书失败 %s: %v", domain, err)
			continue
		}

		certificateMap[domain] = cert
		certificateCount++
		log.Printf("已加载证书: %s", domain)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("迭代证书记录失败: %v", err)
	}

	if certificateCount == 0 {
		log.Println("警告: 没有从数据库加载任何证书")
	} else {
		log.Printf("成功从数据库加载 %d 个证书", certificateCount)
	}

	return nil
}

// generateSelfSignedCert 生成自签名证书
func generateSelfSignedCert(domain string) (certPEM []byte, keyPEM []byte, err error) {
	// 1. 生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("生成私钥失败: %v", err)
	}

	// 2. 创建证书模板
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, nil, fmt.Errorf("生成序列号失败: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 有效期 1 年
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}

	// 3. 生成证书
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("生成证书失败: %v", err)
	}

	// 4. 编码为 PEM 格式
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return certPEM, keyPEM, nil
}

// 生成测试证书并插入数据库
func generateAndInsertTestCertificate() (int64, error) {
	// 生成自签名证书（用于测试）
	certPEM, keyPEM, err := generateSelfSignedCert("kabubu.com")
	if err != nil {
		return 0, err
	}

	// 插入证书到数据库
	insertCert := `INSERT INTO certificates (name, cert_text, key_text) VALUES (?, ?, ?)`
	result, err := db.Exec(insertCert, "kabubu.com测试证书", certPEM, keyPEM)
	if err != nil {
		return 0, fmt.Errorf("插入证书失败: %v", err)
	}

	certID, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("获取证书ID失败: %v", err)
	}

	fmt.Printf("测试证书已生成并插入数据库，证书ID: %d\n", certID)
	return certID, nil
}


func matchesWildcard(serverName, pattern string) bool {
    if len(pattern) > 1 && pattern[0] == '*' && pattern[1] == '.' {
        // 通配符证书匹配: *.example.com
        patternDomain := pattern[2:] // 去掉 "*."
        serverNameDomain := serverName
        if len(serverName) > len(patternDomain) {
            serverNameDomain = serverName[len(serverName)-len(patternDomain):]
        }
        return serverNameDomain == patternDomain
    }
    return false
}

func getCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
    // 从 SNI 获取域名
    serverName := clientHello.ServerName
    
    if cert, ok := certificateMap[serverName]; ok {
        log.Printf("使用证书: %s", serverName)
        return &cert, nil
    }

    // 如果没有找到精确匹配，尝试通配符匹配
    for domain, cert := range certificateMap {
        if matchesWildcard(serverName, domain) {
            log.Printf("使用通配符证书: %s -> %s", serverName, domain)
            return &cert, nil
    }
    }

    // 返回默认证书（第一个证书）
    for _, cert := range certificateMap {
        log.Printf("使用默认证书 for: %s", serverName)
        return &cert, nil
    }

    return nil, nil
}




func ReverseProxy() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)

	tlsConfig := &tls.Config{
        GetCertificate: getCertificate,
  
      MinVersion:     tls.VersionTLS12, // 安全配置
    }

	// HTTP server
	httpSrv := &http.Server{
		Addr:    ":80",
		Handler: mux,
	}

	// HTTPS server
	httpsSrv := &http.Server{
		Addr:    ":443",
		Handler: mux,
		TLSConfig: tlsConfig,
	}

	// 并行启动
	go func() {
		log.Println("HTTP on :80")
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP启动失败: %v", err)
		}
	}()


	log.Println("HTTPS on :443")
    if err := httpsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
        log.Fatalf("HTTPS启动失败: %v", err)
    }
}

func ReadConfig() {
	confFile, err := os.ReadFile("conf.json")
	if err != nil {
		panic(fmt.Errorf("读取 conf.json 失败: %v", err))
	}

	if err := json.Unmarshal(confFile, &cfg); err != nil {
		panic(fmt.Errorf("解析 conf.json 失败: %v", err))
	}
}

func setAdmin() {
	username = "fox"
	password, _ = generateRandomPassword(8)
	tokenStr, err := generateRandomPassword(8)
	if err != nil {
    	tokenStr = "defaultToken"
	}
	jsonTokenKey = []byte(tokenStr)

	// 创建蓝色输出
	fmt.Print("\033[H\033[2J")
	fmt.Println("------------------------账户信息---------------------------")
	blue := color.New(color.FgHiBlue).SprintFunc()
	fmt.Printf("账户密码为: %s:%s\n\n\n\n\n", blue(username), blue(password))
	fmt.Println("-----------------------------------------------------------")
}


func main() {
	setAdmin()
	ReadConfig()
	initDb()
	readRule()
	readWafHtml()
	readBase64()
	
	go statsPrinter()
	go StartGinAPI()
	ReverseProxy()

}