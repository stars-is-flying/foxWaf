package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"

	// "crypto/md5"
	"archive/zip"
	"embed"
	"encoding/csv"
	"os/exec"
	"sort"
	"strconv"

	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	_ "github.com/mutecomm/go-sqlcipher/v4"
	"gopkg.in/yaml.v3"

	stdlog "log"

	// 使用别名
	rand1 "math/rand"
	"runtime/debug"
)

// 添加 embed 指令来嵌入静态文件
//
//go:embed static/*
var staticFiles embed.FS

//go:embed static/waf/*
var wafFiles embed.FS

//go:embed static/out/*
var prismFiles embed.FS

// ------------------- JS混淆配置 -------------------
var EnableJSObfuscation = false // 是否启用JS混淆

// ------------------- JS混淆器 (Level 2) -------------------
type JSObfuscator struct {
	varCounter int
	varMap     map[string]string
	usedVars   map[string]bool
}

func NewJSObfuscator() *JSObfuscator {
	rand1.Seed(time.Now().UnixNano())
	return &JSObfuscator{
		varMap:   make(map[string]string),
		usedVars: make(map[string]bool),
	}
}

// 生成随机变量名
func (o *JSObfuscator) generateRandomVar() string {
	var newName string

	for {
		// Level 2: 带下划线的变量
		newName = fmt.Sprintf("_%x", o.varCounter+1000)

		// 确保变量名唯一
		if !o.usedVars[newName] {
			o.usedVars[newName] = true
			break
		}
		o.varCounter++
	}

	o.varCounter++
	return newName
}

// 保留字检查
func (o *JSObfuscator) isReservedWord(word string) bool {
	reserved := []string{
		"window", "document", "console", "alert", "function", "var", "let", "const",
		"if", "else", "for", "while", "do", "switch", "case", "break", "continue",
		"return", "new", "this", "typeof", "instanceof", "void", "delete", "try",
		"catch", "finally", "throw", "class", "extends", "super", "export", "import",
		"default", "true", "false", "null", "undefined", "NaN", "Infinity",
		"Object", "Array", "String", "Number", "Boolean", "Date", "Math", "JSON",
		"setTimeout", "setInterval", "Promise", "async", "await",
	}

	for _, rw := range reserved {
		if strings.ToLower(word) == strings.ToLower(rw) {
			return true
		}
	}
	return false
}

// 混淆变量名
func (o *JSObfuscator) obfuscateVariables(code string) string {
	// 匹配变量声明和函数声明
	patterns := []string{
		`\b(var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\b`,
		`\bfunction\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(`,
		`\b([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*function\s*\(`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		code = re.ReplaceAllStringFunc(code, func(match string) string {
			var originalName string

			if strings.Contains(match, "function") {
				// 处理函数声明
				if strings.Contains(match, "=") {
					// 函数表达式
					parts := strings.Split(match, "=")
					originalName = strings.TrimSpace(parts[0])
				} else {
					// 函数声明
					parts := strings.Split(match, "function")
					if len(parts) > 1 {
						namePart := strings.TrimSpace(parts[1])
						if idx := strings.Index(namePart, "("); idx != -1 {
							originalName = strings.TrimSpace(namePart[:idx])
						}
					}
				}
			} else {
				// 处理变量声明
				parts := strings.Fields(match)
				if len(parts) >= 2 {
					originalName = parts[1]
				}
			}

			if originalName != "" && !o.isReservedWord(originalName) {
				if newName, exists := o.varMap[originalName]; exists {
					return strings.Replace(match, originalName, newName, 1)
				} else {
					newName := o.generateRandomVar()
					o.varMap[originalName] = newName
					return strings.Replace(match, originalName, newName, 1)
				}
			}

			return match
		})
	}

	// 替换变量使用
	for originalName, newName := range o.varMap {
		// 使用单词边界来避免部分匹配
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(originalName) + `\b`)
		code = re.ReplaceAllString(code, newName)
	}

	return code
}

// 十六进制转义
func (o *JSObfuscator) hexEscapeString(s string) string {
	var result strings.Builder
	result.WriteString(`"`)
	for i := 0; i < len(s); i++ {
		if rand1.Intn(2) == 0 {
			result.WriteString(fmt.Sprintf("\\x%02x", s[i]))
		} else {
			result.WriteByte(s[i])
		}
	}
	result.WriteString(`"`)
	return result.String()
}

// 混淆字符串
func (o *JSObfuscator) obfuscateStrings(code string) string {
	strPattern := `"([^"\\]*(\\.[^"\\]*)*)"|'([^'\\]*(\\.[^'\\]*)*)'`
	re := regexp.MustCompile(strPattern)

	return re.ReplaceAllStringFunc(code, func(match string) string {
		if len(match) < 2 {
			return match
		}

		// 提取字符串内容
		content := match[1 : len(match)-1]

		// 跳过太短的字符串
		if len(content) < 2 {
			return match
		}

		// Level 2: 十六进制转义
		return o.hexEscapeString(content)
	})
}

// 数字混淆
func (o *JSObfuscator) obfuscateNumbers(code string) string {
	// 匹配数字
	numPattern := `\b\d+\b`
	re := regexp.MustCompile(numPattern)

	return re.ReplaceAllStringFunc(code, func(match string) string {
		num, err := strconv.Atoi(match)
		if err != nil {
			return match
		}

		// 跳过 0 和 1，因为它们太常见
		if num == 0 || num == 1 {
			return match
		}

		// 简单的数学表达式
		operations := []string{
			fmt.Sprintf("(%d*%d)", num, 1),
			fmt.Sprintf("(%d+%d)", num-1, 1),
			fmt.Sprintf("(%d/%d)", num*2, 2),
		}
		return operations[rand1.Intn(len(operations))]
	})
}

// 插入无用代码
func (o *JSObfuscator) insertDeadCode(code string) string {
	lines := strings.Split(code, "\n")
	var result []string

	deadCodeTemplates := []string{
		"!![];",
		"void 0;",
		"~-1;",
		"delete null;",
		"typeof undefined;",
		"false;",
		"true;",
		"null;",
	}

	for _, line := range lines {
		result = append(result, line)
		// 在合适的行后插入死代码
		if rand1.Intn(4) == 0 && strings.Contains(line, "{") {
			deadCode := "    " + deadCodeTemplates[rand1.Intn(len(deadCodeTemplates))]
			result = append(result, deadCode)
		} else if rand1.Intn(5) == 0 && strings.Contains(line, ";") && !strings.Contains(line, "}") {
			deadCode := deadCodeTemplates[rand1.Intn(len(deadCodeTemplates))]
			result = append(result, deadCode)
		}
	}

	return strings.Join(result, "\n")
}

// 主混淆函数
func (o *JSObfuscator) Obfuscate(jsCode string) string {
	// 重置状态
	o.varCounter = 0
	o.varMap = make(map[string]string)
	o.usedVars = make(map[string]bool)

	var result string = jsCode

	// 应用混淆技术
	result = o.obfuscateVariables(result)
	result = o.obfuscateStrings(result)
	result = o.obfuscateNumbers(result)
	result = o.insertDeadCode(result)

	return result
}

// 配置相关结构体
type ServerConfig struct {
	Addr string `yaml:"addr"`
	Port int    `yaml:"port"`
}

type DatabaseConfig struct {
	Host          string `yaml:"host"`
	Port          int    `yaml:"port"`
	User          string `yaml:"user"`
	Password      string `yaml:"password"`
	DBName        string `yaml:"dbname"`
	EncryptionKey string `yaml:"encryption_key"`
}

type Config struct {
	Server        ServerConfig   `yaml:"server"`
	Database      DatabaseConfig `yaml:"database"`
	IsWriteDbAuto bool           `yaml:"isWriteDbAuto"`
	Secure        string         `yaml:"secureentry"`
}

var cfg Config // 全局配置

var ccManager *CCManager

var blockedRuleId []string = make([]string, 0)

func getBlockedRuleId(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"id": blockedRuleId,
	})
}

// ------------------- 初始化CC管理器 -------------------
func initCCManager() {
	ccManager = &CCManager{
		rules:    make([]CCRule, 0),
		counters: make(map[string]*ClientCounter),
	}

	// 从数据库加载CC规则
	loadCCRulesFromDB()

	// 启动定时清理过期的计数器
	go ccManager.cleanupWorker()
}

// ------------------- 从数据库加载CC规则 -------------------
// 修复所有数据库查询，确保正确关闭
func loadCCRulesFromDB() {
	ccManager.mutex.Lock()
	defer ccManager.mutex.Unlock()

	query := `SELECT id, name, domain, path, rate_limit, time_window, action, enabled, description FROM cc_rules ORDER BY id ASC`

	rows, err := db.Query(query)
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			createCCTable()
			return
		}
		stdlog.Printf("加载 CC 规则失败: %v", err)
		return
	}
	defer rows.Close()

	ccManager.rules = make([]CCRule, 0)

	for rows.Next() {
		var rule CCRule
		err := rows.Scan(
			&rule.ID, &rule.Name, &rule.Domain, &rule.Path,
			&rule.RateLimit, &rule.TimeWindow, &rule.Action,
			&rule.Enabled, &rule.Description,
		)
		if err != nil {
			stdlog.Printf("读取 CC 规则失败: %v", err)
			continue
		}
		ccManager.rules = append(ccManager.rules, rule)
	}

	// 检查rows错误
	if err := rows.Err(); err != nil {
		stdlog.Printf("遍历CC规则行时出错: %v", err)
	}

	stdlog.Printf("加载了 %d 条 CC 规则", len(ccManager.rules))
}

// ------------------- 创建CC规则表 -------------------
func createCCTable() {
	createTable := `
        CREATE TABLE IF NOT EXISTS cc_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            domain TEXT NOT NULL,
            path TEXT DEFAULT '',
            rate_limit INTEGER NOT NULL,
            time_window INTEGER NOT NULL,
            action TEXT NOT NULL DEFAULT 'block',
            enabled INTEGER NOT NULL DEFAULT 1,
            description TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `

	_, err := db.Exec(createTable)
	if err != nil {
		stdlog.Printf("创建 CC 规则表失败: %v", err)
		return
	}

	// 创建CC攻击日志表
	createLogTable := `
        CREATE TABLE IF NOT EXISTS cc_attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_ip TEXT NOT NULL,
            domain TEXT NOT NULL,
            path TEXT DEFAULT '',
            rule_id INTEGER NOT NULL,
            rule_name TEXT NOT NULL,
            count INTEGER NOT NULL,
            action TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `

	_, err = db.Exec(createLogTable)
	if err != nil {
		stdlog.Printf("创建 CC 攻击日志表失败: %v", err)
	}

	// 插入一些默认规则
	insertDefaultCCRules()
}

// ------------------- 插入默认CC规则 -------------------
func insertDefaultCCRules() {
	defaultRules := []CCRule{
		{
			Name:        "全局CC防护",
			Domain:      "*",
			Path:        "",
			RateLimit:   100,
			TimeWindow:  10,
			Action:      "block",
			Enabled:     true,
			Description: "全局CC攻击防护，10秒内超过100次请求则拦截",
		},
		{
			Name:        "登录接口防护",
			Domain:      "*",
			Path:        "/login",
			RateLimit:   10,
			TimeWindow:  60,
			Action:      "block",
			Enabled:     true,
			Description: "登录接口CC防护，60秒内超过10次请求则拦截",
		},
	}

	insertQuery := `
        INSERT INTO cc_rules (name, domain, path, rate_limit, time_window, action, enabled, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `

	for _, rule := range defaultRules {
		_, err := db.Exec(
			insertQuery,
			rule.Name, rule.Domain, rule.Path, rule.RateLimit,
			rule.TimeWindow, rule.Action, rule.Enabled, rule.Description,
		)
		if err != nil {
			stdlog.Printf("插入默认 CC 规则失败: %v", err)
		}
	}

	stdlog.Println("CC 默认规则已插入")
}

// ------------------- CC检测逻辑 -------------------
func (c *CCManager) checkCC(clientIP, domain, path string) (bool, *CCRule) {
	// 先获取读锁来检查规则
	c.mutex.RLock()

	// 检查所有启用的规则
	var matchedRules []CCRule
	for _, rule := range c.rules {
		if !rule.Enabled {
			continue
		}

		// 检查域名匹配
		if rule.Domain != "*" && rule.Domain != domain {
			continue
		}

		// 检查路径匹配
		if rule.Path != "" {
			matched, _ := filepath.Match(rule.Path, path)
			if !matched {
				continue
			}
		}

		// 保存匹配的规则
		matchedRules = append(matchedRules, rule)
	}

	// 如果没有匹配的规则，直接返回
	if len(matchedRules) == 0 {
		c.mutex.RUnlock()
		return false, nil
	}

	// 释放读锁，获取写锁进行计数器操作
	c.mutex.RUnlock()
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	counterKey := fmt.Sprintf("%s:%s:%s", clientIP, domain, path)

	// 再次检查计数器
	for _, rule := range matchedRules {
		counter, exists := c.counters[counterKey]

		if !exists {
			counter = &ClientCounter{
				IP:       clientIP,
				Domain:   domain,
				Path:     path,
				Count:    1,
				LastTime: now,
			}
			c.counters[counterKey] = counter
			continue
		}

		// 重置过期的计数器
		if now.Sub(counter.LastTime).Seconds() > float64(rule.TimeWindow) {
			counter.Count = 1
			counter.LastTime = now
			counter.Blocked = false
			continue
		}

		// 增加计数
		counter.Count++
		counter.LastTime = now

		// 检查是否超过限制
		if counter.Count > rule.RateLimit && !counter.Blocked {
			counter.Blocked = true
			counter.BlockUntil = now.Add(time.Duration(rule.TimeWindow) * time.Second)

			// 记录攻击日志 - 使用规则的副本避免并发问题
			ruleCopy := rule
			go c.logCCAttack(clientIP, domain, path, &ruleCopy, counter.Count)

			return true, &ruleCopy
		}

		// 如果还在封锁期内，直接拦截
		if counter.Blocked && now.Before(counter.BlockUntil) {
			return true, &rule
		}

		// 封锁期结束，重置状态
		if counter.Blocked && now.After(counter.BlockUntil) {
			counter.Blocked = false
			counter.Count = 0
		}
	}

	return false, nil
}

// ------------------- 记录CC攻击日志 -------------------
func (c *CCManager) logCCAttack(clientIP, domain, path string, rule *CCRule, count int) {
	query := `
        INSERT INTO cc_attack_logs (client_ip, domain, path, rule_id, rule_name, count, action)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `

	_, err := db.Exec(query, clientIP, domain, path, rule.ID, rule.Name, count, rule.Action)
	if err != nil {
		stdlog.Printf("记录CC攻击日志失败: %v", err)
	}
}

// ------------------- 定时清理过期的计数器 -------------------
// 改进CC管理器的清理机制
func (c *CCManager) cleanupWorker() {
	ticker := time.NewTicker(30 * time.Second) // 减少清理间隔
	defer ticker.Stop()

	for range ticker.C {
		c.mutex.Lock()
		now := time.Now()
		cleanedCount := 0

		for key, counter := range c.counters {
			// 清理超过30分钟未活动的计数器
			if now.Sub(counter.LastTime).Minutes() > 30 {
				delete(c.counters, key)
				cleanedCount++
			}
		}

		c.mutex.Unlock()

		if cleanedCount > 0 {
			stdlog.Printf("CC计数器清理: 清理了 %d 个过期计数器", cleanedCount)
		}
	}
}

// ------------------- 获取CC统计信息 -------------------
func (c *CCManager) getStats() CCStats {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	var stats CCStats

	// 总拦截次数
	err := db.QueryRow("SELECT COUNT(*) FROM cc_attack_logs").Scan(&stats.TotalBlocked)
	if err != nil {
		stdlog.Printf("查询CC总拦截数失败: %v", err)
	}

	// 今日拦截次数
	today := time.Now().Format("2006-01-02")
	err = db.QueryRow("SELECT COUNT(*) FROM cc_attack_logs WHERE date(created_at) = ?", today).Scan(&stats.TodayBlocked)
	if err != nil {
		stdlog.Printf("查询CC今日拦截数失败: %v", err)
	}

	// 活跃攻击数（当前被封锁的IP数）
	activeCount := 0
	for _, counter := range c.counters {
		if counter.Blocked && time.Now().Before(counter.BlockUntil) {
			activeCount++
		}
	}
	stats.ActiveAttacks = activeCount

	// 最常被拦截的IP
	rows, err := db.Query(`
        SELECT client_ip, COUNT(*) as count, MAX(created_at) as last_seen 
        FROM cc_attack_logs 
        WHERE created_at >= datetime('now', '-24 hours')
        GROUP BY client_ip 
        ORDER BY count DESC 
        LIMIT 10
    `)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var ip BlockedIP
			var lastSeen time.Time
			rows.Scan(&ip.IP, &ip.Count, &lastSeen)
			ip.LastSeen = lastSeen.Format("2006-01-02 15:04:05")
			stats.TopBlockedIPs = append(stats.TopBlockedIPs, ip)
		}
	}

	// 规则统计
	rows, err = db.Query(`
        SELECT rule_id, rule_name, COUNT(*) as blocked 
        FROM cc_attack_logs 
        WHERE created_at >= datetime('now', '-24 hours')
        GROUP BY rule_id, rule_name 
        ORDER BY blocked DESC
    `)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var ruleStat CCRuleStat
			rows.Scan(&ruleStat.RuleID, &ruleStat.RuleName, &ruleStat.Blocked)
			stats.RuleStats = append(stats.RuleStats, ruleStat)
		}
	}

	return stats
}

// ------------------- 添加CC规则请求 -------------------
type AddCCRuleRequest struct {
	Name        string `json:"name" binding:"required"`
	Domain      string `json:"domain" binding:"required"`
	Path        string `json:"path"`
	RateLimit   int    `json:"rate_limit" binding:"min=1"`
	TimeWindow  int    `json:"time_window" binding:"min=1"`
	Action      string `json:"action" binding:"oneof=block challenge"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
}

// ------------------- 添加CC规则接口 -------------------
func addCCRuleHandler(c *gin.Context) {
	var req AddCCRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 插入数据库
	query := `
        INSERT INTO cc_rules (name, domain, path, rate_limit, time_window, action, enabled, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `

	result, err := db.Exec(
		query,
		req.Name, req.Domain, req.Path, req.RateLimit,
		req.TimeWindow, req.Action, req.Enabled, req.Description,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("插入CC规则失败: %v", err)})
		return
	}

	id, _ := result.LastInsertId()

	// 热更新内存规则
	ccManager.mutex.Lock()
	newRule := CCRule{
		ID:          int(id),
		Name:        req.Name,
		Domain:      req.Domain,
		Path:        req.Path,
		RateLimit:   req.RateLimit,
		TimeWindow:  req.TimeWindow,
		Action:      req.Action,
		Enabled:     req.Enabled,
		Description: req.Description,
	}
	ccManager.rules = append(ccManager.rules, newRule)
	ccManager.mutex.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"message": "CC规则添加成功",
		"id":      id,
	})
}

// ------------------- 获取CC规则列表接口 -------------------
func getCCRulesHandler(c *gin.Context) {
	ccManager.mutex.RLock()
	defer ccManager.mutex.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"rules": ccManager.rules,
		"count": len(ccManager.rules),
	})
}

// ------------------- 更新CC规则请求 -------------------
type UpdateCCRuleRequest struct {
	Name        string `json:"name"`
	Domain      string `json:"domain"`
	Path        string `json:"path"`
	RateLimit   int    `json:"rate_limit" binding:"min=1"`
	TimeWindow  int    `json:"time_window" binding:"min=1"`
	Action      string `json:"action" binding:"oneof=block challenge"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
}

// ------------------- 更新CC规则接口 -------------------
func updateCCRuleHandler(c *gin.Context) {
	ruleID := c.Param("id")

	var req UpdateCCRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 更新数据库
	query := `
        UPDATE cc_rules 
        SET name = ?, domain = ?, path = ?, rate_limit = ?, time_window = ?, action = ?, enabled = ?, description = ?
        WHERE id = ?
    `

	result, err := db.Exec(
		query,
		req.Name, req.Domain, req.Path, req.RateLimit,
		req.TimeWindow, req.Action, req.Enabled, req.Description, ruleID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("更新CC规则失败: %v", err)})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "规则不存在"})
		return
	}

	// 热更新内存规则
	ccManager.mutex.Lock()
	for i, rule := range ccManager.rules {
		if fmt.Sprintf("%d", rule.ID) == ruleID {
			ccManager.rules[i] = CCRule{
				ID:          rule.ID,
				Name:        req.Name,
				Domain:      req.Domain,
				Path:        req.Path,
				RateLimit:   req.RateLimit,
				TimeWindow:  req.TimeWindow,
				Action:      req.Action,
				Enabled:     req.Enabled,
				Description: req.Description,
			}
			break
		}
	}
	ccManager.mutex.Unlock()

	c.JSON(http.StatusOK, gin.H{"message": "CC规则更新成功"})
}

// ------------------- 删除CC规则接口 -------------------
func deleteCCRuleHandler(c *gin.Context) {
	ruleID := c.Param("id")

	_, err := db.Exec("DELETE FROM cc_rules WHERE id = ?", ruleID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("删除CC规则失败: %v", err)})
		return
	}

	// 热更新内存规则
	ccManager.mutex.Lock()
	for i, rule := range ccManager.rules {
		if fmt.Sprintf("%d", rule.ID) == ruleID {
			ccManager.rules = append(ccManager.rules[:i], ccManager.rules[i+1:]...)
			break
		}
	}
	ccManager.mutex.Unlock()

	c.JSON(http.StatusOK, gin.H{"message": "CC规则删除成功"})
}

// ------------------- 获取CC统计接口 -------------------
func getCCStatsHandler(c *gin.Context) {
	stats := ccManager.getStats()
	c.JSON(http.StatusOK, stats)
}

// ------------------- 获取CC攻击日志接口 -------------------
type CCAttackLogQuery struct {
	Page      int    `form:"page" binding:"min=1"`
	PageSize  int    `form:"page_size" binding:"min=1,max=100"`
	ClientIP  string `form:"client_ip"`
	Domain    string `form:"domain"`
	RuleID    string `form:"rule_id"`
	StartTime string `form:"start_time"`
	EndTime   string `form:"end_time"`
}

type CCAttackLogResponse struct {
	Logs       []CCAttackLog `json:"logs"`
	Total      int           `json:"total"`
	Page       int           `json:"page"`
	PageSize   int           `json:"page_size"`
	TotalPages int           `json:"total_pages"`
}

func getCCAttackLogsHandler(c *gin.Context) {
	var query CCAttackLogQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 设置默认值
	if query.Page == 0 {
		query.Page = 1
	}
	if query.PageSize == 0 {
		query.PageSize = 20
	}

	// 构建查询条件
	whereClause := "WHERE 1=1"
	args := []interface{}{}

	if query.ClientIP != "" {
		whereClause += " AND client_ip = ?"
		args = append(args, query.ClientIP)
	}

	if query.Domain != "" {
		whereClause += " AND domain = ?"
		args = append(args, query.Domain)
	}

	if query.RuleID != "" {
		whereClause += " AND rule_id = ?"
		args = append(args, query.RuleID)
	}

	if query.StartTime != "" {
		whereClause += " AND created_at >= ?"
		args = append(args, query.StartTime)
	}

	if query.EndTime != "" {
		whereClause += " AND created_at <= ?"
		args = append(args, query.EndTime)
	}

	// 查询总数
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM cc_attack_logs %s", whereClause)
	var total int
	err := db.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("查询总数失败: %v", err)})
		return
	}

	// 查询数据
	dataQuery := fmt.Sprintf(`
        SELECT id, client_ip, domain, path, rule_id, rule_name, count, action, created_at 
        FROM cc_attack_logs %s 
        ORDER BY created_at DESC 
        LIMIT ? OFFSET ?
    `, whereClause)

	offset := (query.Page - 1) * query.PageSize
	args = append(args, query.PageSize, offset)

	rows, err := db.Query(dataQuery, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("查询CC攻击日志失败: %v", err)})
		return
	}
	defer rows.Close()

	var logs []CCAttackLog
	for rows.Next() {
		var log CCAttackLog
		err := rows.Scan(
			&log.ID, &log.ClientIP, &log.Domain, &log.Path,
			&log.RuleID, &log.RuleName, &log.Count, &log.Action, &log.CreatedAt,
		)
		if err != nil {
			stdlog.Printf("读取CC攻击日志失败: %v", err)
			continue
		}
		logs = append(logs, log)
	}

	totalPages := (total + query.PageSize - 1) / query.PageSize

	response := CCAttackLogResponse{
		Logs:       logs,
		Total:      total,
		Page:       query.Page,
		PageSize:   query.PageSize,
		TotalPages: totalPages,
	}

	c.JSON(http.StatusOK, response)
}

// ------------------- 清空CC计数器接口 -------------------
func clearCCCountersHandler(c *gin.Context) {
	ccManager.mutex.Lock()
	ccManager.counters = make(map[string]*ClientCounter)
	ccManager.mutex.Unlock()

	c.JSON(http.StatusOK, gin.H{"message": "CC计数器已清空"})
}

// ------------------- 规则 -------------------
// 规则相关结构体
type Judge struct {
	Position string         `yaml:"position" binding:"required"`
	Content  string         `yaml:"content"`
	Rix      string         `yaml:"rix"`
	Action   string         `yaml:"action"`
	regex    *regexp.Regexp `yaml:"-"`
}

type Rule struct {
	Name        string  `yaml:"name"`
	Description string  `yaml:"description"`
	ID          string  `yaml:"id"`
	Method      string  `yaml:"method"`
	Relation    string  `yaml:"relation"`
	Judges      []Judge `yaml:"judge"`
	Enabled     bool    `yaml:"enabled"`
}

var RULES map[string][]Rule

// ------------------- 攻击记录 -------------------
// ------------------- 攻击记录 -------------------
type AttackLog struct {
	Method       string `json:"method"`
	URL          string `json:"url"`
	Headers      string `json:"headers"`
	Body         string `json:"body"`
	RuleName     string `json:"rule_name"`
	RuleID       string `json:"rule_id"`
	MatchedValue string `json:"matched_value"`
	ClientIP     string `json:"client_ip"` // 新增客户端IP字段
}

// 上游服务器
type UpstreamServer struct {
	ID        int
	SiteID    int
	URL       string
	Weight    int
	Status    int // 1启用 0禁用
	CreatedAt string
}

// 站点
type Site struct {
	ID                   int
	Name                 string
	Domain               string
	TargetURL            string // 保留兼容，如果启用负载均衡则不使用
	EnableHTTPS          bool
	CERTID               sql.NullInt64
	Status               int
	LoadBalanceAlgorithm string           // "round_robin" 或 "weighted" 或 ""(不使用负载均衡)
	CreatedAt            string           // 可以用 time.Time
	UpdatedAt            string           // 可以用 time.Time
	UpstreamServers      []UpstreamServer // 上游服务器列表
}

// ------------------- 攻击日志查询参数 -------------------
type AttackLogQuery struct {
	Page      int    `form:"page" binding:"min=1"`
	PageSize  int    `form:"page_size" binding:"min=1,max=100"`
	Method    string `form:"method"`
	RuleName  string `form:"rule_name"`
	RuleID    string `form:"rule_id"`
	StartTime string `form:"start_time"`
	EndTime   string `form:"end_time"`
	Search    string `form:"search"`
}

// ------------------- 攻击日志响应结构 -------------------
type AttackLogResponse struct {
	ID           int    `json:"id"`
	Method       string `json:"method"`
	URL          string `json:"url"`
	Headers      string `json:"headers"`
	Body         string `json:"body"`
	RuleName     string `json:"rule_name"`
	RuleID       string `json:"rule_id"`
	MatchedValue string `json:"matched_value"`
	ClientIP     string `json:"client_ip"` // 新增
	CreatedAt    string `json:"created_at"`

	// 解码后的字段（可选展示）
	URLDecoded     string `json:"url_decoded,omitempty"`
	HeadersDecoded string `json:"headers_decoded,omitempty"`
	BodyDecoded    string `json:"body_decoded,omitempty"`
}

// ------------------- 攻击日志分页响应 -------------------
type AttackLogPageResponse struct {
	Logs       []AttackLogResponse `json:"logs"`
	Total      int                 `json:"total"`
	Page       int                 `json:"page"`
	PageSize   int                 `json:"page_size"`
	TotalPages int                 `json:"total_pages"`
}

// ------------------- 攻击统计响应 -------------------
type AttackStatsResponse struct {
	TotalAttacks int          `json:"total_attacks"`
	TodayAttacks int          `json:"today_attacks"`
	TopRules     []RuleStat   `json:"top_rules"`
	TopMethods   []MethodStat `json:"top_methods"`
	HourlyStats  []HourlyStat `json:"hourly_stats"`
}

// ------------------- CC规则 -------------------
type CCRule struct {
	ID          int    `json:"id"`
	Name        string `json:"name" binding:"required"`
	Domain      string `json:"domain" binding:"required"`              // 应用的域名
	Path        string `json:"path"`                                   // 路径模式，空表示全站
	RateLimit   int    `json:"rate_limit" binding:"min=1"`             // 请求次数
	TimeWindow  int    `json:"time_window" binding:"min=1"`            // 时间窗口(秒)
	Action      string `json:"action" binding:"oneof=block challenge"` // 拦截动作
	Enabled     bool   `json:"enabled"`                                // 是否启用
	Description string `json:"description"`                            // 规则描述
}

// ------------------- CC攻击记录 -------------------
type CCAttackLog struct {
	ID        int    `json:"id"`
	ClientIP  string `json:"client_ip"`
	Domain    string `json:"domain"`
	Path      string `json:"path"`
	RuleID    int    `json:"rule_id"`
	RuleName  string `json:"rule_name"`
	Count     int    `json:"count"`
	Action    string `json:"action"`
	CreatedAt string `json:"created_at"`
}

// ------------------- CC规则管理器 -------------------
type CCManager struct {
	rules    []CCRule
	counters map[string]*ClientCounter // key: "ip:domain:path"
	mutex    sync.RWMutex
}

// ------------------- 客户端计数器 -------------------
type ClientCounter struct {
	IP         string
	Domain     string
	Path       string
	Count      int
	LastTime   time.Time
	Blocked    bool
	BlockUntil time.Time
}

// ------------------- CC统计 -------------------
type CCStats struct {
	TotalBlocked  int          `json:"total_blocked"`
	TodayBlocked  int          `json:"today_blocked"`
	ActiveAttacks int          `json:"active_attacks"`
	TopBlockedIPs []BlockedIP  `json:"top_blocked_ips"`
	RuleStats     []CCRuleStat `json:"rule_stats"`
}

type BlockedIP struct {
	IP       string `json:"ip"`
	Count    int    `json:"count"`
	LastSeen string `json:"last_seen"`
}

type CCRuleStat struct {
	RuleID   int    `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Blocked  int    `json:"blocked"`
}

type RuleStat struct {
	RuleName string `json:"rule_name"`
	RuleID   string `json:"rule_id"`
	Count    int    `json:"count"`
}

type MethodStat struct {
	Method string `json:"method"`
	Count  int    `json:"count"`
}

type HourlyStat struct {
	Hour  string `json:"hour"`
	Count int    `json:"count"`
}

// ------------------- 流量统计相关结构体 -------------------
type TrafficLog struct {
	ID           int64     `json:"id"`
	Domain       string    `json:"domain"`
	Path         string    `json:"path"`
	Method       string    `json:"method"`
	StatusCode   int       `json:"status_code"`
	ClientIP     string    `json:"client_ip"`
	UserAgent    string    `json:"user_agent"`
	Referer      string    `json:"referer"`
	RequestSize  int64     `json:"request_size"`
	ResponseSize int64     `json:"response_size"`
	ResponseTime int64     `json:"response_time"` // 响应时间（毫秒）
	CacheStatus  string    `json:"cache_status"`  // HIT, MISS, BYPASS
	CreatedAt    time.Time `json:"created_at"`
}

type TrafficStats struct {
	TotalRequests   int64         `json:"total_requests"`
	TodayRequests   int64         `json:"today_requests"`
	TotalBytes      int64         `json:"total_bytes"`
	TodayBytes      int64         `json:"today_bytes"`
	AvgResponseTime float64       `json:"avg_response_time"`
	CacheHitRate    float64       `json:"cache_hit_rate"`
	StatusCodes     map[int]int64 `json:"status_codes"`
	TopDomains      []DomainStat  `json:"top_domains"`
	TopPaths        []PathStat    `json:"top_paths"`
	TopIPs          []IPStat      `json:"top_ips"`
	HourlyStats     []HourlyStat  `json:"hourly_stats"`
	MethodStats     []MethodStat  `json:"method_stats"`
	RecentTraffic   []TrafficLog  `json:"recent_traffic"`
}

type DomainStat struct {
	Domain   string  `json:"domain"`
	Requests int64   `json:"requests"`
	Bytes    int64   `json:"bytes"`
	AvgTime  float64 `json:"avg_time"`
}

type PathStat struct {
	Path     string  `json:"path"`
	Requests int64   `json:"requests"`
	Bytes    int64   `json:"bytes"`
	AvgTime  float64 `json:"avg_time"`
}

type IPStat struct {
	IP       string `json:"ip"`
	Requests int64  `json:"requests"`
	Bytes    int64  `json:"bytes"`
	LastSeen string `json:"last_seen"`
}

// ------------------- 删除攻击日志请求 -------------------
type DeleteAttackLogsRequest struct {
	IDs    []int  `json:"ids"`    // 指定ID删除
	Before string `json:"before"` // 删除指定时间之前的记录
	All    bool   `json:"all"`    // 删除所有记录
}

// ------------------- 删除攻击日志接口 -------------------
func deleteAttackLogsHandler(c *gin.Context) {
	var req DeleteAttackLogsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var result sql.Result
	var err error

	if req.All {
		// 删除所有记录
		result, err = db.Exec("DELETE FROM attacks")
	} else if len(req.IDs) > 0 {
		// 删除指定ID的记录
		query := "DELETE FROM attacks WHERE id IN (" + strings.Repeat("?,", len(req.IDs)-1) + "?)"
		args := make([]interface{}, len(req.IDs))
		for i, id := range req.IDs {
			args[i] = id
		}
		result, err = db.Exec(query, args...)
	} else if req.Before != "" {
		// 删除指定时间之前的记录
		result, err = db.Exec("DELETE FROM attacks WHERE created_at < ?", req.Before)
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请提供删除条件"})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("删除失败: %v", err)})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	c.JSON(http.StatusOK, gin.H{
		"message":       "攻击日志删除成功",
		"rows_affected": rowsAffected,
	})

}

// ------------------- 导出攻击日志接口 -------------------
// ------------------- 导出攻击日志查询参数 -------------------
type ExportAttackLogQuery struct {
	Method    string `form:"method"`
	RuleName  string `form:"rule_name"`
	RuleID    string `form:"rule_id"`
	StartTime string `form:"start_time"`
	EndTime   string `form:"end_time"`
	Search    string `form:"search"`
}

// ------------------- 修改导出攻击日志接口 -------------------
func exportAttackLogsHandler(c *gin.Context) {
	var query ExportAttackLogQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 构建查询条件
	whereClause := "WHERE 1=1"
	args := []interface{}{}

	if query.Method != "" {
		whereClause += " AND method = ?"
		args = append(args, query.Method)
	}

	if query.RuleName != "" {
		whereClause += " AND rule_name LIKE ?"
		args = append(args, "%"+query.RuleName+"%")
	}

	if query.RuleID != "" {
		whereClause += " AND rule_id = ?"
		args = append(args, query.RuleID)
	}

	if query.StartTime != "" {
		whereClause += " AND created_at >= ?"
		args = append(args, query.StartTime)
	}

	if query.EndTime != "" {
		whereClause += " AND created_at <= ?"
		args = append(args, query.EndTime)
	}

	if query.Search != "" {
		whereClause += " AND (matched_value LIKE ? OR rule_name LIKE ?)"
		args = append(args, "%"+query.Search+"%", "%"+query.Search+"%")
	}

	// 查询数据 - 导出所有匹配的记录，不分页
	dataQuery := fmt.Sprintf(`
    SELECT id, method, url, headers, body, rule_name, rule_id, matched_value, client_ip, created_at 
    FROM attacks %s 
    ORDER BY created_at DESC
`, whereClause)

	rows, err := db.Query(dataQuery, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("查询日志失败: %v", err)})
		return
	}
	defer rows.Close()

	var logs []AttackLogResponse
	for rows.Next() {
		var log AttackLogResponse
		var urlB64, headersB64, bodyB64 string

		err := rows.Scan(
			&log.ID, &log.Method, &urlB64, &headersB64, &bodyB64,
			&log.RuleName, &log.RuleID, &log.MatchedValue, &log.ClientIP, &log.CreatedAt,
		)
		if err != nil {
			continue
		}

		// Base64 解码
		if urlDecoded, err := base64.StdEncoding.DecodeString(urlB64); err == nil {
			log.URL = string(urlDecoded)
		}
		if headersDecoded, err := base64.StdEncoding.DecodeString(headersB64); err == nil {
			log.Headers = string(headersDecoded)
		}
		if bodyDecoded, err := base64.StdEncoding.DecodeString(bodyB64); err == nil {
			log.Body = string(bodyDecoded)
		}

		logs = append(logs, log)
	}

	// 设置响应头
	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", "attachment; filename=attack_logs.csv")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")

	// 写入CSV
	writer := csv.NewWriter(c.Writer)
	defer writer.Flush()

	// 写入表头
	writer.Write([]string{
		"ID", "时间", "方法", "规则名称", "规则ID", "匹配内容", "客户端IP", "URL", "请求头", "请求体",
	})

	// 写入数据
	for _, log := range logs {
		writer.Write([]string{
			fmt.Sprintf("%d", log.ID),
			log.CreatedAt,
			log.Method,
			log.RuleName,
			log.RuleID,
			truncateString(log.MatchedValue, 100),
			log.ClientIP,
			truncateString(log.URL, 100),
			truncateString(log.Headers, 100),
			truncateString(log.Body, 100),
		})
	}
}

// 截断字符串
func truncateString(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length] + "..."
}

// ------------------- 获取攻击统计接口 -------------------
func getAttackStatsHandler(c *gin.Context) {
	var stats AttackStatsResponse

	// 总攻击次数
	err := db.QueryRow("SELECT COUNT(*) FROM attacks").Scan(&stats.TotalAttacks)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("查询总攻击数失败: %v", err)})
		return
	}

	// 今日攻击次数
	today := time.Now().Format("2006-01-02")
	err = db.QueryRow("SELECT COUNT(*) FROM attacks WHERE DATE(created_at) = ?", today).Scan(&stats.TodayAttacks)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("查询今日攻击数失败: %v", err)})
		return
	}

	// 最常触发的规则
	rows, err := db.Query(`
        SELECT rule_name, rule_id, COUNT(*) as count 
        FROM attacks 
        GROUP BY rule_name, rule_id 
        ORDER BY count DESC 
        LIMIT 10
    `)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var rule RuleStat
			rows.Scan(&rule.RuleName, &rule.RuleID, &rule.Count)
			stats.TopRules = append(stats.TopRules, rule)
		}
	}

	// 攻击方法分布
	rows, err = db.Query(`
        SELECT method, COUNT(*) as count 
        FROM attacks 
        GROUP BY method 
        ORDER BY count DESC
    `)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var method MethodStat
			rows.Scan(&method.Method, &method.Count)
			stats.TopMethods = append(stats.TopMethods, method)
		}
	}

	// 24小时攻击趋势
	rows, err = db.Query(`
        SELECT DATE_FORMAT(created_at, '%Y-%m-%d %H:00:00') as hour, COUNT(*) as count 
        FROM attacks 
        WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        GROUP BY hour 
        ORDER BY hour
    `)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var hourly HourlyStat
			rows.Scan(&hourly.Hour, &hourly.Count)
			stats.HourlyStats = append(stats.HourlyStats, hourly)
		}
	}

	c.JSON(http.StatusOK, stats)
}

// ------------------- 获取攻击日志接口 -------------------
// ------------------- 修复获取攻击日志接口 -------------------
func getAttackLogsHandler(c *gin.Context) {
	var query AttackLogQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 设置默认值
	if query.Page == 0 {
		query.Page = 1
	}
	if query.PageSize == 0 {
		query.PageSize = 20
	}

	// 构建查询条件
	whereClause := "WHERE 1=1"
	args := []interface{}{}

	if query.Method != "" {
		whereClause += " AND method = ?"
		args = append(args, query.Method)
	}

	if query.RuleName != "" {
		whereClause += " AND rule_name LIKE ?"
		args = append(args, "%"+query.RuleName+"%")
	}

	if query.RuleID != "" {
		whereClause += " AND rule_id = ?"
		args = append(args, query.RuleID)
	}

	if query.StartTime != "" {
		whereClause += " AND created_at >= ?"
		args = append(args, query.StartTime)
	}

	if query.EndTime != "" {
		whereClause += " AND created_at <= ?"
		args = append(args, query.EndTime)
	}

	if query.Search != "" {
		whereClause += " AND (matched_value LIKE ? OR rule_name LIKE ?)"
		args = append(args, "%"+query.Search+"%", "%"+query.Search+"%")
	}

	// 查询总数
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM attacks %s", whereClause)
	var total int
	err := db.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("查询总数失败: %v", err)})
		return
	}

	// 查询数据
	dataQuery := fmt.Sprintf(`
        SELECT id, method, url, headers, body, rule_name, rule_id, matched_value, client_ip, created_at 
        FROM attacks %s 
        ORDER BY created_at DESC 
        LIMIT ? OFFSET ?
    `, whereClause)

	offset := (query.Page - 1) * query.PageSize
	args = append(args, query.PageSize, offset)

	rows, err := db.Query(dataQuery, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("查询日志失败: %v", err)})
		return
	}
	defer rows.Close()

	var logs []AttackLogResponse
	for rows.Next() {
		var log AttackLogResponse
		var urlB64, headersB64, bodyB64 string

		err := rows.Scan(
			&log.ID, &log.Method, &urlB64, &headersB64, &bodyB64,
			&log.RuleName, &log.RuleID, &log.MatchedValue, &log.ClientIP, &log.CreatedAt,
		)
		if err != nil {
			stdlog.Printf("读取攻击日志失败: %v", err)
			continue
		}

		// Base64 解码
		if urlDecoded, err := base64.StdEncoding.DecodeString(urlB64); err == nil {
			log.URL = string(urlDecoded)
		} else {
			log.URL = urlB64
		}

		if headersDecoded, err := base64.StdEncoding.DecodeString(headersB64); err == nil {
			log.Headers = string(headersDecoded)
		} else {
			log.Headers = headersB64
		}

		if bodyDecoded, err := base64.StdEncoding.DecodeString(bodyB64); err == nil {
			log.Body = string(bodyDecoded)
		} else {
			log.Body = bodyB64
		}

		logs = append(logs, log)
	}

	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("迭代日志失败: %v", err)})
		return
	}

	totalPages := (total + query.PageSize - 1) / query.PageSize

	response := AttackLogPageResponse{
		Logs:       logs,
		Total:      total,
		Page:       query.Page,
		PageSize:   query.PageSize,
		TotalPages: totalPages,
	}

	c.JSON(http.StatusOK, response)
}

// ------------------- 获取单个攻击日志详情接口 -------------------
func getAttackLogDetailHandler(c *gin.Context) {
	logID := c.Param("id")

	if logID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "日志ID不能为空"})
		return
	}

	query := `
        SELECT id, method, url, headers, body, rule_name, rule_id, matched_value, client_ip,created_at 
        FROM attacks 
        WHERE id = ?
    `

	var log AttackLogResponse
	var urlB64, headersB64, bodyB64 string

	err := db.QueryRow(query, logID).Scan(
		&log.ID, &log.Method, &urlB64, &headersB64, &bodyB64,
		&log.RuleName, &log.RuleID, &log.MatchedValue, &log.ClientIP, &log.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "日志不存在"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("查询日志详情失败: %v", err)})
		}
		return
	}

	// Base64 解码
	if urlDecoded, err := base64.StdEncoding.DecodeString(urlB64); err == nil {
		log.URL = string(urlDecoded)
		// 添加URL解码版本（多次解码）
		log.URLDecoded = MultiDecode(string(urlDecoded))
	} else {
		log.URL = urlB64
		log.URLDecoded = MultiDecode(urlB64)
	}

	if headersDecoded, err := base64.StdEncoding.DecodeString(headersB64); err == nil {
		log.Headers = string(headersDecoded)
		log.HeadersDecoded = MultiDecode(string(headersDecoded))
	} else {
		log.Headers = headersB64
		log.HeadersDecoded = MultiDecode(headersB64)
	}

	if bodyDecoded, err := base64.StdEncoding.DecodeString(bodyB64); err == nil {
		log.Body = string(bodyDecoded)
		log.BodyDecoded = MultiDecode(string(bodyDecoded))
	} else {
		log.Body = bodyB64
		log.BodyDecoded = MultiDecode(bodyB64)
	}

	c.JSON(http.StatusOK, gin.H{
		"log": log,
	})
}

// 管理员信息
var username string
var password string
var jsonTokenKey []byte

var sites []Site
var certificateMap = map[string]tls.Certificate{}

// 负载均衡：每个站点的轮询计数器
var roundRobinCounters = make(map[int]*int64)
var roundRobinMutex sync.RWMutex

// 负载均衡：权重算法的随机数生成器
var lbRand *rand1.Rand

// 选择上游服务器
func selectUpstreamServer(site *Site) *UpstreamServer {
	if site == nil || len(site.UpstreamServers) == 0 {
		return nil
	}

	// 过滤出启用的服务器
	availableServers := make([]UpstreamServer, 0)
	for _, server := range site.UpstreamServers {
		if server.Status == 1 {
			availableServers = append(availableServers, server)
		}
	}

	if len(availableServers) == 0 {
		return nil
	}

	switch site.LoadBalanceAlgorithm {
	case "round_robin":
		// 轮询算法
		roundRobinMutex.Lock()
		defer roundRobinMutex.Unlock()

		counter, exists := roundRobinCounters[site.ID]
		if !exists {
			var val int64 = 0
			counter = &val
			roundRobinCounters[site.ID] = counter
		}

		idx := int(atomic.LoadInt64(counter)) % len(availableServers)
		atomic.AddInt64(counter, 1)

		return &availableServers[idx]

	case "weighted":
		// 权重算法
		totalWeight := 0
		for _, server := range availableServers {
			if server.Weight > 0 {
				totalWeight += server.Weight
			}
		}

		if totalWeight == 0 {
			// 如果所有权重都是0，退回到轮询
			if lbRand == nil {
				lbRand = rand1.New(rand1.NewSource(time.Now().UnixNano()))
			}
			idx := lbRand.Intn(len(availableServers))
			return &availableServers[idx]
		}

		// 随机选择一个权重范围内的值
		randomWeight := lbRand.Intn(totalWeight) + 1
		currentWeight := 0

		for i := range availableServers {
			currentWeight += availableServers[i].Weight
			if randomWeight <= currentWeight {
				return &availableServers[i]
			}
		}

		// 默认返回第一个
		return &availableServers[0]

	default:
		// 默认返回第一个可用的服务器
		return &availableServers[0]
	}
}

var attackChan = make(chan AttackLog, 1000)
var workerCount = 5
var db *sql.DB

// ------------------- 内存统计 -------------------
var totalRequests uint64
var totalBlocked uint64

// ---------base64Decode------------------
var maxDepth = 2
var isActivateBase64 = true

//---------urlDecode-----------------------

var maxUrlDepth = 2
var isActivateUrlDecode = true

// 百分比（0~100）控制要用多少规则
var RuleMatchRate int = 100 // 默认 100% 使用

// ------------注入防开发者模式-----------------
var EnableAntiDevTools = false

// ------------------- 添加站点接口 -------------------
type AddSiteRequest struct {
	Name                 string              `json:"name" binding:"required"`
	Domain               string              `json:"domain" binding:"required"`
	TargetURL            string              `json:"target_url"` // 如果启用负载均衡则为可选
	EnableHTTPS          bool                `json:"enable_https"`
	CertName             string              `json:"cert_name"`              // 可选，自动生成自签名
	LoadBalanceAlgorithm string              `json:"load_balance_algorithm"` // "" 或 "round_robin" 或 "weighted"
	UpstreamServers      []UpstreamServerAdd `json:"upstream_servers"`
}

type UpstreamServerAdd struct {
	URL    string `json:"url"`
	Weight int    `json:"weight"`
}

// ------------------------------静态缓存加速----------------------------------
// ------------------- 静态文件缓存配置 -------------------
type StaticCacheConfig struct {
	Enable          bool          // 是否开启静态缓存
	CacheDir        string        // 缓存目录
	MaxCacheSize    int64         // 最大缓存大小（字节）
	DefaultExpire   time.Duration // 默认缓存过期时间
	CleanupInterval time.Duration // 缓存清理间隔
}

type CachedFile struct {
	Content      []byte
	ContentType  string
	Size         int64
	LastModified time.Time
	ExpireAt     time.Time
}

var staticCacheConfig = StaticCacheConfig{
	Enable:          false,             // 默认开启
	CacheDir:        "./static_cache",  // 缓存目录
	MaxCacheSize:    100 * 1024 * 1024, // 100MB
	DefaultExpire:   24 * time.Hour,    // 24小时
	CleanupInterval: 1 * time.Hour,     // 1小时清理一次
}

var (
	fileCache        = make(map[string]*CachedFile) // 内存缓存
	cacheMutex       sync.RWMutex
	currentCacheSize int64
	cacheHits        uint64
	cacheMisses      uint64
)

// -------------------站点心跳------------------------
// 站点健康状态结构
type SiteHealth struct {
	SiteID               int                    `json:"site_id"`
	Domain               string                 `json:"domain"`
	IsAlive              bool                   `json:"is_alive"`
	Status               int                    `json:"status"`
	Latency              int64                  `json:"latency"` // 毫秒
	LastCheck            string                 `json:"last_check"`
	ErrorMsg             string                 `json:"error_msg,omitempty"`
	UpstreamServerHealth []UpstreamServerHealth `json:"upstream_server_health,omitempty"` // 上游服务器健康状态
}

type UpstreamServerHealth struct {
	URL      string `json:"url"`
	Weight   int    `json:"weight,omitempty"`
	IsAlive  bool   `json:"is_alive"`
	Latency  int64  `json:"latency"` // 毫秒
	ErrorMsg string `json:"error_msg,omitempty"`
}

// 全局健康状态映射
var siteHealthMap = make(map[int]*SiteHealth)
var healthMutex sync.RWMutex

// 检查单个URL的健康状态
func checkURLHealth(url, domain string) UpstreamServerHealth {
	result := UpstreamServerHealth{
		URL:     url,
		IsAlive: false,
	}

	start := time.Now()

	// 创建HTTP客户端，设置超时
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// 先尝试HEAD请求
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		result.ErrorMsg = fmt.Sprintf("创建HEAD请求失败: %v", err)
		result.Latency = time.Since(start).Milliseconds()
		return result
	}

	// 添加请求头
	req.Header.Set("User-Agent", "LittleFox-WAF-HealthCheck/1.0")
	if domain != "" {
		req.Header.Set("Host", domain)
	}

	resp, err := client.Do(req)
	if err != nil {
		// HEAD失败，尝试GET请求
		req, err = http.NewRequest("GET", url, nil)
		if err != nil {
			result.ErrorMsg = fmt.Sprintf("创建GET请求失败: %v", err)
			result.Latency = time.Since(start).Milliseconds()
			return result
		}

		req.Header.Set("User-Agent", "LittleFox-WAF-HealthCheck/1.0")
		if domain != "" {
			req.Header.Set("Host", domain)
		}

		resp, err = client.Do(req)
		if err != nil {
			result.ErrorMsg = fmt.Sprintf("GET请求失败: %v", err)
			result.Latency = time.Since(start).Milliseconds()
			return result
		}
		defer resp.Body.Close()
	} else {
		defer resp.Body.Close()
	}

	result.Latency = time.Since(start).Milliseconds()

	// 判断HTTP状态码
	if resp.StatusCode >= 0 {
		result.IsAlive = true
	}

	return result
}

// 更健壮的健康检查函数，支持GET和HEAD方法
func checkSiteHealthEnhanced(site Site) *SiteHealth {
	health := &SiteHealth{
		SiteID:    site.ID,
		Domain:    site.Domain,
		LastCheck: time.Now().Format("2006-01-02 15:04:05"),
	}

	// 如果有负载均衡，检查所有上游服务器
	if site.LoadBalanceAlgorithm != "" && len(site.UpstreamServers) > 0 {
		health.UpstreamServerHealth = make([]UpstreamServerHealth, 0, len(site.UpstreamServers))
		for _, upstream := range site.UpstreamServers {
			if upstream.Status == 1 { // 只检查启用的上游服务器
				upstreamHealth := checkURLHealth(upstream.URL, site.Domain)
				upstreamHealth.Weight = upstream.Weight
				health.UpstreamServerHealth = append(health.UpstreamServerHealth, upstreamHealth)
			}
		}
		// 如果至少有一个上游服务器是健康的，则站点是健康的
		health.IsAlive = false
		health.Status = 0
		health.Latency = 0
		for _, usHealth := range health.UpstreamServerHealth {
			if usHealth.IsAlive {
				health.IsAlive = true
				if health.Latency == 0 || health.Latency > usHealth.Latency {
					health.Latency = usHealth.Latency
				}
				health.Status = 200
			}
		}
		if !health.IsAlive {
			health.ErrorMsg = "所有上游服务器都不可用"
		}
	} else {
		// 没有负载均衡，检查target_url
		start := time.Now()
		testURL := site.TargetURL

		// 创建HTTP客户端，设置超时
		client := &http.Client{
			Timeout: 5 * time.Second,
		}

		// println(testURL)
		// 先尝试HEAD请求
		req, err := http.NewRequest("HEAD", testURL, nil)
		if err != nil {
			health.IsAlive = false
			health.ErrorMsg = fmt.Sprintf("创建HEAD请求失败: %v", err)
			health.Latency = time.Since(start).Milliseconds()
			return health
		}

		// 添加请求头
		req.Header.Set("User-Agent", "LittleFox-WAF-HealthCheck/1.0")
		if site.Domain != "" {
			req.Header.Set("Host", site.Domain)
		}

		resp, err := client.Do(req)
		if err != nil {
			// HEAD失败，尝试GET请求
			// stdlog.Printf("HEAD请求失败，尝试GET: %s - %v", site.Name, err)
			req, err = http.NewRequest("GET", testURL, nil)
			if err != nil {
				health.IsAlive = false
				health.ErrorMsg = fmt.Sprintf("创建GET请求失败: %v", err)
				health.Latency = time.Since(start).Milliseconds()
				return health
			}

			req.Header.Set("User-Agent", "LittleFox-WAF-HealthCheck/1.0")
			if site.Domain != "" {
				req.Header.Set("Host", site.Domain)
			}

			resp, err = client.Do(req)
			if err != nil {
				health.IsAlive = false
				health.ErrorMsg = fmt.Sprintf("GET请求也失败: %v", err)
				health.Latency = time.Since(start).Milliseconds()
				return health
			}
			defer resp.Body.Close()
		} else {
			defer resp.Body.Close()
		}

		health.Latency = time.Since(start).Milliseconds()

		// 判断HTTP状态码
		if resp.StatusCode >= 0 {
			health.IsAlive = true
			health.Status = resp.StatusCode
		} else {
			health.IsAlive = false
			health.Status = resp.StatusCode
			health.ErrorMsg = fmt.Sprintf("HTTP状态码: %d", resp.StatusCode)
		}
	}

	return health
}

// 批量健康检查 - 使用增强版本
func performHealthChecks() {
	// aclManager.mutex.RLock()
	// sitesCopy := make([]Site, len(sites))
	// copy(sitesCopy, sites)
	// aclManager.mutex.RUnlock()

	for _, site := range sites {
		// 只检查启用的站点
		if site.Status == 1 {
			health := checkSiteHealthEnhanced(site)

			healthMutex.Lock()
			siteHealthMap[site.ID] = health
			healthMutex.Unlock()

			// status := "正常"
			// if !health.IsAlive {
			//     status = "异常"
			// }
			// stdlog.Printf("健康检查: %s (%s) -> %s - 状态: %s, 延迟: %dms",
			//     site.Name, site.Domain, site.TargetURL, status, health.Latency)
		} else {
			// 对于停用的站点，标记为未知状态
			healthMutex.Lock()
			siteHealthMap[site.ID] = &SiteHealth{
				SiteID:    site.ID,
				Domain:    site.Domain,
				IsAlive:   false,
				Status:    0,
				Latency:   0,
				LastCheck: time.Now().Format("2006-01-02 15:04:05"),
				ErrorMsg:  "站点已停用",
			}
			healthMutex.Unlock()
		}
	}
}

// 启动定时健康检查
func startHealthChecker() {
	// 立即执行一次检查
	performHealthChecks()

	// 每10秒执行一次检查
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		performHealthChecks()
	}
}

// ------------------- 健康状态API接口 -------------------
func getSiteHealthHandler(c *gin.Context) {
	healthMutex.RLock()
	defer healthMutex.RUnlock()

	// 返回所有站点的健康状态
	healthStatus := make(map[int]*SiteHealth)
	for id, health := range siteHealthMap {
		healthStatus[id] = health
	}

	c.JSON(http.StatusOK, gin.H{
		"health_status": healthStatus,
		"timestamp":     time.Now().Format("2006-01-02 15:04:05"),
	})
}

// 健康检查函数 - 直接请求 target_url
func checkSiteHealth(site Site) *SiteHealth {
	health := &SiteHealth{
		SiteID:    site.ID,
		Domain:    site.Domain,
		LastCheck: time.Now().Format("2006-01-02 15:04:05"),
	}

	start := time.Now()

	// 直接使用 target_url，不需要构建URL
	testURL := site.TargetURL

	// 创建HTTP客户端，设置超时
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// 发送HEAD请求检查站点
	req, err := http.NewRequest("HEAD", testURL, nil)
	if err != nil {
		health.IsAlive = false
		health.ErrorMsg = fmt.Sprintf("创建请求失败: %v", err)
		health.Latency = time.Since(start).Milliseconds()
		return health
	}

	// 添加一些基本的请求头
	req.Header.Set("User-Agent", "LittleFox-WAF-HealthCheck/1.0")
	// 添加Host头，模拟真实请求
	if site.Domain != "" {
		req.Header.Set("Host", site.Domain)
	}

	resp, err := client.Do(req)
	if err != nil {
		health.IsAlive = false
		health.ErrorMsg = fmt.Sprintf("请求失败: %v", err)
		health.Latency = time.Since(start).Milliseconds()
		return health
	}
	defer resp.Body.Close()

	health.Latency = time.Since(start).Milliseconds()

	// 判断HTTP状态码
	if resp.StatusCode >= 0 {
		health.IsAlive = true
		health.Status = resp.StatusCode
	} else {
		health.IsAlive = false
		health.Status = resp.StatusCode
		health.ErrorMsg = fmt.Sprintf("HTTP状态码: %d", resp.StatusCode)
	}

	return health
}

// ------------------- 单个站点健康检查接口 -------------------
func checkSingleSiteHealthHandler(c *gin.Context) {
	siteIDStr := c.Param("id")
	siteID, err := strconv.Atoi(siteIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的站点ID"})
		return
	}

	// 查找站点
	aclManager.mutex.RLock()
	var targetSite Site
	found := false
	for _, site := range sites {
		if site.ID == siteID {
			targetSite = site
			found = true
			break
		}
	}
	aclManager.mutex.RUnlock()

	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "站点不存在"})
		return
	}

	// 执行健康检查
	health := checkSiteHealth(targetSite)

	// 更新全局状态
	healthMutex.Lock()
	siteHealthMap[siteID] = health
	healthMutex.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"health": health,
	})
}

// ------------------- 缓存管理函数 -------------------
func initStaticCache() {
	// 磁盘缓存已移除，只使用内存缓存
	if staticCacheConfig.Enable {
		// 启动定期清理协程
		go cacheCleanupWorker()

		stdlog.Printf("静态文件缓存已启用（仅内存缓存）")
	} else {
		stdlog.Println("静态文件缓存已禁用")
	}
}

// 检查是否为可缓存的静态文件
func isCacheableStaticFile(path string) bool {
	if !staticCacheConfig.Enable {
		return false
	}

	// 静态文件扩展名
	cacheableExts := map[string]bool{
		".css":   true,
		".js":    true,
		".png":   true,
		".jpg":   true,
		".jpeg":  true,
		".gif":   true,
		".svg":   true,
		".ico":   true,
		".woff":  true,
		".woff2": true,
		".ttf":   true,
		".eot":   true,
		".pdf":   true,
		".txt":   true,
		".xml":   true,
		".json":  true,
	}

	ext := strings.ToLower(filepath.Ext(path))
	println(ext)
	return cacheableExts[ext]
}

// ------------------- 修复从缓存获取文件函数 -------------------
func getCachedFile(cacheKey string) (*CachedFile, bool) {
	if !staticCacheConfig.Enable {
		return nil, false
	}

	cacheMutex.RLock()
	cachedFile, exists := fileCache[cacheKey]
	cacheMutex.RUnlock()

	if exists {
		// 检查是否过期
		if time.Now().Before(cachedFile.ExpireAt) {
			atomic.AddUint64(&cacheHits, 1)
			return cachedFile, true
		} else {
			// 过期了，从缓存中移除
			removeFromCache(cacheKey)
		}
	}

	atomic.AddUint64(&cacheMisses, 1)
	return nil, false
}

// 添加到缓存
// 添加到缓存
func addToCache(cacheKey string, content []byte, contentType string) {
	if !staticCacheConfig.Enable {
		return
	}

	var finalContent = content

	// 只有在启用防开发者工具且是HTML内容时才注入脚本
	if EnableAntiDevTools && isHTMLContent(contentType) {
		modifiedContent := injectAntiDevTools(string(content))
		finalContent = []byte(modifiedContent)
	}

	// 新增：如果启用JS混淆且是JavaScript内容，进行混淆
	if EnableJSObfuscation && isJSContent(contentType) {
		obfuscator := NewJSObfuscator()
		obfuscatedJS := obfuscator.Obfuscate(string(content))
		finalContent = []byte(obfuscatedJS)
		stdlog.Printf("JS混淆已应用: %s", cacheKey)
	}

	fileSize := int64(len(finalContent))

	// 检查是否超过最大缓存大小
	if currentCacheSize+fileSize > staticCacheConfig.MaxCacheSize {
		// 如果超过限制，先清理一些旧缓存
		cleanupExpiredCache()
		// 再次检查
		if currentCacheSize+fileSize > staticCacheConfig.MaxCacheSize {
			stdlog.Printf("缓存空间不足，跳过缓存: %s", cacheKey)
			return
		}
	}

	expireAt := time.Now().Add(staticCacheConfig.DefaultExpire)

	cachedFile := &CachedFile{
		Content:      finalContent,
		ContentType:  contentType,
		Size:         fileSize,
		LastModified: time.Now(),
		ExpireAt:     expireAt,
	}

	cacheMutex.Lock()
	// 如果已存在，先移除旧的
	if oldFile, exists := fileCache[cacheKey]; exists {
		currentCacheSize -= oldFile.Size
	}

	fileCache[cacheKey] = cachedFile
	currentCacheSize += fileSize
	cacheMutex.Unlock()

	stdlog.Printf("缓存添加成功: %s, 大小: %.2f KB", cacheKey, float64(fileSize)/1024)
}

// 检查是否为JavaScript内容
func isJSContent(contentType string) bool {
	if contentType == "" {
		return false
	}
	contentType = strings.ToLower(contentType)
	return strings.Contains(contentType, "application/javascript") ||
		strings.Contains(contentType, "text/javascript")
}

// 从缓存移除
func removeFromCache(cacheKey string) {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	if cachedFile, exists := fileCache[cacheKey]; exists {
		currentCacheSize -= cachedFile.Size
		delete(fileCache, cacheKey)
	}
}

// func generateCacheKey(urlPath string) string {
//     hash := md5.Sum([]byte(urlPath))
//     return fmt.Sprintf("cache_%x", hash)
// }

// 缓存清理工作器
func cacheCleanupWorker() {
	ticker := time.NewTicker(staticCacheConfig.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		cleanupExpiredCache()
	}
}

// ------------------- 添加缓存统计接口 -------------------
type CacheStatsDetailResponse struct {
	Enable      bool              `json:"enable"`
	CacheHits   uint64            `json:"cache_hits"`
	CacheMisses uint64            `json:"cache_misses"`
	HitRate     string            `json:"hit_rate"`
	CurrentSize string            `json:"current_size"`
	MaxSize     string            `json:"max_size"`
	CachedFiles int               `json:"cached_files"`
	CacheItems  map[string]string `json:"cache_items,omitempty"`
}

// 获取详细缓存统计
func getCacheStatsDetailHandler(c *gin.Context) {
	cacheMutex.RLock()
	cachedFiles := len(fileCache)
	currentSize := currentCacheSize

	// 获取缓存项详情
	cacheItems := make(map[string]string)
	for key, file := range fileCache {
		cacheItems[key] = fmt.Sprintf("%s, 大小: %.2f KB, 过期: %s",
			file.ContentType,
			float64(file.Size)/1024,
			file.ExpireAt.Format("15:04:05"))
	}
	cacheMutex.RUnlock()

	hits := atomic.LoadUint64(&cacheHits)
	misses := atomic.LoadUint64(&cacheMisses)
	total := hits + misses
	hitRate := "0%"
	if total > 0 {
		hitRate = fmt.Sprintf("%.2f%%", float64(hits)/float64(total)*100)
	}

	stats := CacheStatsDetailResponse{
		Enable:      staticCacheConfig.Enable,
		CacheHits:   hits,
		CacheMisses: misses,
		HitRate:     hitRate,
		CurrentSize: fmt.Sprintf("%.2f MB", float64(currentSize)/(1024*1024)),
		MaxSize:     fmt.Sprintf("%.2f MB", float64(staticCacheConfig.MaxCacheSize)/(1024*1024)),
		CachedFiles: cachedFiles,
		CacheItems:  cacheItems,
	}

	c.JSON(http.StatusOK, stats)
}

// ------------------- 修复缓存清理 -------------------
// 改进缓存清理
func cleanupExpiredCache() {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	now := time.Now()
	cleanedSize := int64(0)
	cleanedCount := 0

	// 首先清理过期的缓存
	for key, cachedFile := range fileCache {
		if now.After(cachedFile.ExpireAt) {
			currentCacheSize -= cachedFile.Size
			cleanedSize += cachedFile.Size
			cleanedCount++
			delete(fileCache, key)
		}
	}

	// 如果仍然超过限制，按LRU清理到限制的70%
	if currentCacheSize > staticCacheConfig.MaxCacheSize {
		targetSize := staticCacheConfig.MaxCacheSize * 70 / 100

		// 按最后修改时间排序
		type cacheItem struct {
			key  string
			file *CachedFile
		}

		var items []cacheItem
		for key, file := range fileCache {
			items = append(items, cacheItem{key, file})
		}

		sort.Slice(items, func(i, j int) bool {
			return items[i].file.LastModified.Before(items[j].file.LastModified)
		})

		for _, item := range items {
			if currentCacheSize <= targetSize {
				break
			}

			currentCacheSize -= item.file.Size
			delete(fileCache, item.key)
			cleanedCount++
			cleanedSize += item.file.Size
		}
	}

	if cleanedCount > 0 {
		stdlog.Printf("缓存清理完成: 清理了 %d 个文件, 释放了 %.2f MB",
			cleanedCount, float64(cleanedSize)/(1024*1024))
	}
}

// 添加全局恢复机制
func safeHandler(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				stdlog.Printf("处理请求时发生panic: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("服务器内部错误"))
			}
		}()
		h(w, r)
	}
}

// ------------------- 添加LRU缓存清理 -------------------
func cleanupLRUCache() {
	// 按最后修改时间排序
	type cacheItem struct {
		key  string
		file *CachedFile
	}

	var items []cacheItem
	for key, file := range fileCache {
		items = append(items, cacheItem{key, file})
	}

	// 按最后修改时间排序（最早的在前）
	sort.Slice(items, func(i, j int) bool {
		return items[i].file.LastModified.Before(items[j].file.LastModified)
	})

	// 清理直到低于限制的80%
	targetSize := staticCacheConfig.MaxCacheSize * 80 / 100
	cleanedCount := 0

	for _, item := range items {
		if currentCacheSize <= targetSize {
			break
		}

		currentCacheSize -= item.file.Size
		delete(fileCache, item.key)
		cleanedCount++

	}

	if cleanedCount > 0 {
		stdlog.Printf("LRU缓存清理: 清理了 %d 个文件, 当前大小: %.2f MB",
			cleanedCount, float64(currentCacheSize)/(1024*1024))
	}
}

var antiDevToolsScript = `
<script>
(function() {
    'use strict';
    
    var devToolsOpened = false;
    var checkInterval = null;
    
    // 检测开发者工具是否开启的多种方法
    function detectDevTools() {
        var widthThreshold = window.outerWidth - window.innerWidth > 160;
        var heightThreshold = window.outerHeight - window.innerHeight > 160;
        
        // 方法1: 窗口大小差异检测
        if (widthThreshold || heightThreshold) {
            return true;
        }
        
        // 方法2: 调试器检测
        var start = performance.now();
        debugger;
        var end = performance.now();
        if (end - start > 100) {
            return true;
        }
        
        // 方法3: 控制台检测
        var element = new Image();
        Object.defineProperty(element, 'id', {
            get: function() {
                return true;
            }
        });
        console.log(element);
        
        // 方法4: 性能监测
        var perfData = window.performance.memory;
        if (perfData && perfData.usedJSHeapSize > 100000000) { // 100MB
            return true;
        }
        
        return false;
    }
    
    // 关闭开发者工具的方法
    function closeDevTools() {
        try {
            // 方法1: 触发窗口调整（可能关闭开发者工具）
            window.resizeTo(window.screen.availWidth, window.screen.availHeight);
            
            // 方法2: 尝试 blur 和 focus
            window.blur();
            window.focus();
            
            // 方法3: 打开新窗口并关闭当前（激进方法）
            // var newWindow = window.open(window.location.href, '_self');
            // if (newWindow) {
            //     window.close();
            // }
            
            // 方法4: 重载页面
            // window.location.reload();
            
        } catch(e) {
            // 静默处理错误
        }
    }
    
    // 强制关闭开发者工具
    function forceCloseDevTools() {
        if (detectDevTools()) {
            devToolsOpened = true;
            console.log('开发者工具已检测到，正在尝试关闭...');
            closeDevTools();
            
            // 如果检测到多次，采取更激进的措施
            setTimeout(function() {
                if (detectDevTools()) {
                    console.log('开发者工具仍然开启，尝试重载页面...');
                    window.location.reload();
                }
            }, 1000);
        }
    }
    
    // 按键阻止
    function blockShortcuts(e) {
        var blockedKeys = [
            {key: 'F12', ctrl: false, shift: false},
            {key: 'I', ctrl: true, shift: true},
            {key: 'J', ctrl: true, shift: true}, 
            {key: 'C', ctrl: true, shift: true},
            {key: 'U', ctrl: true, shift: false},
            {key: 'S', ctrl: true, shift: true} // Ctrl+Shift+S
        ];
        
        for (var i = 0; i < blockedKeys.length; i++) {
            var shortcut = blockedKeys[i];
            if (e.key === shortcut.key && 
                e.ctrlKey === shortcut.ctrl && 
                e.shiftKey === shortcut.shift) {
                e.preventDefault();
                e.stopPropagation();
                e.stopImmediatePropagation();
                
                // 立即检测并尝试关闭开发者工具
                setTimeout(forceCloseDevTools, 100);
                return false;
            }
        }
        
        // 单独检测 F12
        if (e.key === 'F12') {
            e.preventDefault();
            e.stopPropagation();
            e.stopImmediatePropagation();
            setTimeout(forceCloseDevTools, 100);
            return false;
        }
        
        return true;
    }
    
    // 右键阻止
    function blockContextMenu(e) {
        e.preventDefault();
        e.stopPropagation();
        return false;
    }
    
    // 定期检测函数
    function periodicCheck() {
        if (detectDevTools()) {
            console.log('定期检测：发现开发者工具已开启');
            forceCloseDevTools();
        }
    }
    
    // 初始化保护
    function initProtection() {
        // 立即检测一次
        setTimeout(function() {
            forceCloseDevTools();
        }, 500);
        
        // 每5秒定期检测
        checkInterval = setInterval(periodicCheck, 5000);
        
        // 添加事件监听
        document.addEventListener('keydown', blockShortcuts, true);
        document.addEventListener('contextmenu', blockContextMenu, true);
        
        // 监听窗口大小变化（开发者工具可能改变窗口）
        var lastWidth = window.innerWidth;
        var lastHeight = window.innerHeight;
        
        window.addEventListener('resize', function() {
            var widthDiff = Math.abs(window.innerWidth - lastWidth);
            var heightDiff = Math.abs(window.innerHeight - lastHeight);
            
            if (widthDiff > 100 || heightDiff > 100) {
                setTimeout(forceCloseDevTools, 300);
            }
            
            lastWidth = window.innerWidth;
            lastHeight = window.innerHeight;
        });
        
        // 监听页面可见性变化
        document.addEventListener('visibilitychange', function() {
            if (!document.hidden) {
                setTimeout(forceCloseDevTools, 1000);
            }
        });
        
        // 控制台干扰
        if (window.console) {
            var methods = ['log', 'warn', 'error', 'info', 'debug', 'clear'];
            methods.forEach(function(method) {
                if (console[method]) {
                    var original = console[method];
                    console[method] = function() {
                        // 记录到后台（可选）
                        // logToServer('Console used: ' + method, arguments);
                        
                        try {
                            original.apply(console, arguments);
                        } catch(e) {
                            // 静默失败
                        }
                    };
                }
            });
            
            // 重写 console 对象本身
            Object.defineProperty(window, 'console', {
                value: console,
                writable: false,
                configurable: false
            });
        }
        
        // 防止在新窗口打开开发者工具
        window.open = function() {
            return null;
        };
    }
    
    // 页面加载完成后初始化
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initProtection);
    } else {
        initProtection();
    }
    
    // 提供清理函数（可选）
    window.disableAntiDevTools = function() {
        if (checkInterval) {
            clearInterval(checkInterval);
        }
        document.removeEventListener('keydown', blockShortcuts, true);
        document.removeEventListener('contextmenu', blockContextMenu, true);
    };
    
})();
</script>
`

// ------------------- 修复HTML内容检查 -------------------
func isHTMLContent(contentType string) bool {
	if contentType == "" {
		return false
	}
	contentType = strings.ToLower(contentType)
	return strings.Contains(contentType, "text/html") ||
		strings.Contains(contentType, "application/xhtml+xml")
}

func injectAntiDevTools(htmlContent string) string {
	// 检查是否已经包含防开发者工具脚本
	if strings.Contains(htmlContent, "detectDevTools") ||
		strings.Contains(htmlContent, "blockDevTools") ||
		strings.Contains(htmlContent, "devToolsOpened") {
		return htmlContent
	}

	// 在head标签中注入
	if strings.Contains(htmlContent, "</head>") {
		return strings.Replace(htmlContent, "</head>", antiDevToolsScript+"</head>", 1)
	}

	// 在body开始标签后注入
	if strings.Contains(htmlContent, "<body") {
		// 找到body开始标签的位置
		bodyStart := strings.Index(htmlContent, "<body")
		if bodyStart != -1 {
			// 找到body标签的结束位置
			bodyEnd := strings.Index(htmlContent[bodyStart:], ">")
			if bodyEnd != -1 {
				insertPos := bodyStart + bodyEnd + 1
				return htmlContent[:insertPos] + antiDevToolsScript + htmlContent[insertPos:]
			}
		}
	}

	// 在html结束标签前注入
	if strings.Contains(htmlContent, "</html>") {
		return strings.Replace(htmlContent, "</html>", antiDevToolsScript+"</html>", 1)
	}

	// 直接追加到末尾
	return htmlContent + antiDevToolsScript
}

var httpTransport *http.Transport

func init() {
	httpTransport = &http.Transport{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     false, // 启用连接复用
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // 添加这一行来跳过证书验证
		},
	}

	// 初始化负载均衡随机数生成器
	lbRand = rand1.New(rand1.NewSource(time.Now().UnixNano()))
}

func handler(w http.ResponseWriter, req *http.Request) {
	atomic.AddUint64(&totalRequests, 1)

	// 记录请求开始时间
	startTime := time.Now()

	// 初始化流量记录变量
	var trafficRecorded bool
	var requestSize int64
	var responseSize int64
	var statusCode int
	var cacheStatus string = "BYPASS"
	var domain string
	var path string

	defer func() {
		// 确保在函数退出前记录流量
		if !trafficRecorded && domain != "" {
			clientIP := getClientIP(req)
			userAgent := req.Header.Get("User-Agent")
			referer := req.Header.Get("Referer")
			responseTime := time.Since(startTime).Milliseconds()

			logTraffic(domain, path, req.Method, statusCode, clientIP, userAgent, referer,
				requestSize, responseSize, responseTime, cacheStatus)
		}
	}()

	// 检查是否为 WebSocket 升级请求
	if strings.ToLower(req.Header.Get("Upgrade")) == "websocket" {
		// 查找目标站点
		host := req.Host
		var targetURL string

		for i := range sites {
			if strings.EqualFold(sites[i].Domain, host) && sites[i].Status == 1 {
				// 负载均衡选择上游服务器
				if sites[i].LoadBalanceAlgorithm != "" && len(sites[i].UpstreamServers) > 0 {
					selectedServer := selectUpstreamServer(&sites[i])
					if selectedServer != nil {
						targetURL = selectedServer.URL
					} else {
						targetURL = sites[i].TargetURL
					}
				} else {
					targetURL = sites[i].TargetURL
				}
				break
			}
		}

		if targetURL == "" {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(NotFoundPage))
			return
		}

		// 解析目标 URL 并创建 WebSocket 代理
		backendURL, err := url.Parse(targetURL)
		if err != nil {
			stdlog.Printf("解析目标URL失败: %v", err)
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(proxyErrorPage))
			return
		}

		proxy := &websocketProxy{backendURL: backendURL}
		proxy.serveWS(w, req)
		return
	}

	// 第一步：计算 Content-Length，决定是否跳过 WAF 检测
	var requestBody []byte
	const maxWAFBodySize int64 = 2 * 1024 * 1024 // 2MB
	var skipWAF bool
	// 尝试获取内容长度
	contentLength := req.ContentLength
	if contentLength <= 0 {
		if clStr := req.Header.Get("Content-Length"); clStr != "" {
			if clParsed, err := strconv.ParseInt(clStr, 10, 64); err == nil {
				contentLength = clParsed
			}
		}
	}
	if contentLength > maxWAFBodySize {
		skipWAF = true
		stdlog.Printf("请求体过大(%d bytes)，跳过 WAF 检测，直接转发", contentLength)
	} else {
		// 小体或未知长度：读取请求体供 WAF 检测与后续转发
		if req.Body != nil {
			var err error
			requestBody, err = io.ReadAll(req.Body)
			if err != nil {
				stdlog.Printf("读取请求体失败: %v", err)
			}
		}
	}

	// 第二步：所有安全检查使用保存的请求体副本
	// 查找目标站点
	host := req.Host
	var targetURL string
	var enableHTTPS bool
	var siteDomain string
	var siteHost string
	var attacked bool
	var log *AttackLog
	var clientIP string
	var ccBlocked bool
	var ccRule *CCRule
	var currentSite *Site // 保存当前站点信息，用于后续重试

	for i := range sites {
		if strings.EqualFold(sites[i].Domain, host) && sites[i].Status == 1 {
			currentSite = &sites[i]
			enableHTTPS = sites[i].EnableHTTPS
			siteDomain = sites[i].Domain

			// 负载均衡选择上游服务器
			if sites[i].LoadBalanceAlgorithm != "" && len(sites[i].UpstreamServers) > 0 {
				selectedServer := selectUpstreamServer(&sites[i])
				if selectedServer != nil {
					targetURL = selectedServer.URL
				} else {
					// 如果没有可用的上游服务器，回退到原来的target_url
					targetURL = sites[i].TargetURL
				}
			} else {
				// 未启用负载均衡，使用原来的target_url
				targetURL = sites[i].TargetURL
			}

			if targetURL != "" {
				siteHost = strings.Split(targetURL, "://")[1]
			}
			break
		}
	}

	if targetURL == "" {
		domain = host
		path = req.URL.Path
		statusCode = http.StatusNotFound
		requestSize = req.ContentLength
		if requestSize <= 0 {
			requestSize = int64(len(requestBody))
		}
		responseSize = int64(len(NotFoundPage))
		cacheStatus = "BYPASS"
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(NotFoundPage))
		return
	}

	// 1. 先检查 ACL 规则
	blocked, aclRule := aclManager.checkACL(req, host)
	if blocked {
		atomic.AddUint64(&totalBlocked, 1)
		stdlog.Printf("ACL 拦截: %s %s, 规则: %s", getClientIP(req), req.URL.Path, aclRule.Description)
		domain = siteDomain
		path = req.URL.Path
		statusCode = http.StatusForbidden
		requestSize = req.ContentLength
		if requestSize <= 0 {
			requestSize = int64(len(requestBody))
		}
		responseSize = int64(len(aclBlock))
		cacheStatus = "BYPASS"
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(aclBlock))
		return
	}

	// 如果 ACL 规则是 allow，直接跳转到代理请求
	if aclRule != nil && aclRule.Action == "allow" {
		stdlog.Printf("ACL 允许: %s %s, 规则: %s", getClientIP(req), req.URL.Path, aclRule.Description)
		goto DIRECT_PROXY
	}

	// 检查CC规则
	clientIP = getClientIP(req)
	ccBlocked, ccRule = ccManager.checkCC(clientIP, host, req.URL.Path)
	if ccBlocked {
		atomic.AddUint64(&totalBlocked, 1)
		stdlog.Printf("CC 拦截: %s %s%s, 规则: %s", clientIP, host, req.URL.Path, ccRule.Name)
		domain = siteDomain
		path = req.URL.Path
		statusCode = http.StatusTooManyRequests
		requestSize = req.ContentLength
		if requestSize <= 0 {
			requestSize = int64(len(requestBody))
		}
		responseSize = int64(len(ccBlockPage))
		cacheStatus = "BYPASS"
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(ccBlockPage))
		return
	}

	// 2. 再检查 WAF 规则 - 使用保存的请求体副本
	// 临时设置请求体供 WAF 检查
	if len(requestBody) > 0 {
		req.Body = io.NopCloser(bytes.NewBuffer(requestBody))
	}
	// 2. 再检查 WAF 规则 - 仅在未跳过时
	if !skipWAF {
		if len(requestBody) > 0 {
			req.Body = io.NopCloser(bytes.NewBuffer(requestBody))
		}
		attacked, log = isAttack(req)
		if attacked {
			atomic.AddUint64(&totalBlocked, 1)
			domain = siteDomain
			path = req.URL.Path
			statusCode = http.StatusForbidden
			requestSize = req.ContentLength
			if requestSize <= 0 {
				requestSize = int64(len(requestBody))
			}
			if cfg.IsWriteDbAuto {
				attackChan <- *log
				responseSize = int64(len(interceptPage))
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(interceptPage))
			} else {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(log)
				responseSize = 1024 // 估算JSON大小
			}
			cacheStatus = "BYPASS"
			return
		}
	}

DIRECT_PROXY:
	// 3. 检查静态文件缓存
	if staticCacheConfig.Enable && req.Method == "GET" {
		cacheKey := siteDomain + req.URL.Path
		if cachedFile, found := getCachedFile(cacheKey); found {
			domain = siteDomain
			path = req.URL.Path
			statusCode = http.StatusOK
			requestSize = req.ContentLength
			if requestSize <= 0 {
				requestSize = int64(len(requestBody))
			}
			responseSize = int64(cachedFile.Size)
			cacheStatus = "HIT"
			w.Header().Set("Content-Type", cachedFile.ContentType)
			w.Header().Set("Content-Length", fmt.Sprintf("%d", cachedFile.Size))
			w.Header().Set("Cache-Control", "public, max-age=3600")
			w.Header().Set("X-Cache", "HIT")
			w.Header().Set("X-Cache-Key", cacheKey)
			w.WriteHeader(http.StatusOK)
			w.Write(cachedFile.Content)
			stdlog.Printf("缓存命中: %s%s", host, req.URL.Path)

			// 记录流量统计
			clientIP := getClientIP(req)
			userAgent := req.Header.Get("User-Agent")
			referer := req.Header.Get("Referer")
			responseTime := time.Since(startTime).Milliseconds()

			logTraffic(domain, path, req.Method, statusCode, clientIP, userAgent, referer,
				requestSize, responseSize, responseTime, cacheStatus)
			trafficRecorded = true
			return
		}
	}

	// 第四步：构造代理请求 - 小体用内存，大体保持原始流式
	var bodyReader io.Reader
	if skipWAF {
		// 使用原始 req.Body 流式转发，避免内存化
		bodyReader = req.Body
	} else if len(requestBody) > 0 {
		bodyReader = bytes.NewBuffer(requestBody)
	} else {
		bodyReader = nil
	}

	proxyReq, err := http.NewRequest(req.Method, targetURL+req.RequestURI, bodyReader)
	if err != nil {
		stdlog.Printf("创建反向代理请求失败: %v", err)
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(proxyErrorPage))
		return
	}

	// 设置重要属性
	proxyReq.Host = siteHost

	// 拷贝请求头（优化版）
	for k, v := range req.Header {
		if k == "Accept-Encoding" {
			continue
		}
		proxyReq.Header[k] = v
	}

	transport := &http.Transport{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// 调试：输出发送的请求 - 使用保存的请求体
	// fmt.Printf("\n🚀 代理请求到后端站点: %s\n", targetURL+req.RequestURI)
	// debugPrintRequestWithBody(proxyReq, requestBody)

	// 添加调试：验证代理请求体内容
	if proxyReq.Body != nil {
		// 临时读取代理请求的 Body 来验证内容
		tempBody, err := io.ReadAll(proxyReq.Body)
		if err != nil {
			stdlog.Printf("检查代理请求体失败: %v", err)
		} else {
			stdlog.Printf("代理请求体验证 - 长度: %d bytes", len(tempBody))
			if len(tempBody) > 0 {
				stdlog.Printf("代理请求体验证 - 前100字符: %.100s", string(tempBody))
			} else {
				stdlog.Printf("警告: 代理请求体验证 - 为空!")
			}
			// 重置 Body
			proxyReq.Body = io.NopCloser(bytes.NewBuffer(tempBody))
		}
	}

	if enableHTTPS {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	client := &http.Client{
		Transport: httpTransport,
		Timeout:   30 * time.Second,
	}

	// 发送请求
	resp, err := client.Do(proxyReq)
	if err != nil {
		stdlog.Printf("请求目标站点失败: %v", err)

		// 尝试重试到其他上游服务器
		if currentSite != nil && currentSite.LoadBalanceAlgorithm != "" && len(currentSite.UpstreamServers) > 0 {
			stdlog.Printf("尝试切换到其他上游服务器...")

			// 收集所有可用的上游服务器
			var alternativeURLs []string
			for _, us := range currentSite.UpstreamServers {
				if us.Status == 1 && us.URL != targetURL {
					alternativeURLs = append(alternativeURLs, us.URL)
				}
			}

			// 尝试其他上游服务器
			for _, altURL := range alternativeURLs {
				stdlog.Printf("尝试上游服务器: %s", altURL)
				altHost := strings.Split(altURL, "://")[1]

				// 重新创建请求体
				var altBodyReader io.Reader
				if skipWAF {
					altBodyReader = req.Body
				} else if len(requestBody) > 0 {
					altBodyReader = bytes.NewBuffer(requestBody)
				} else {
					altBodyReader = nil
				}

				// 创建新的代理请求
				altProxyReq, altErr := http.NewRequest(req.Method, altURL+req.RequestURI, altBodyReader)
				if altErr != nil {
					stdlog.Printf("创建重试请求失败: %v", altErr)
					continue
				}

				altProxyReq.Host = altHost
				for k, v := range req.Header {
					if k == "Accept-Encoding" {
						continue
					}
					altProxyReq.Header[k] = v
				}

				// 尝试发送请求
				altResp, altErr := client.Do(altProxyReq)
				if altErr == nil {
					stdlog.Printf("重试成功，切换到上游服务器: %s", altURL)
					resp = altResp
					err = nil
					siteHost = altHost
					break
				} else {
					stdlog.Printf("重试失败: %s, 错误: %v", altURL, altErr)
					if altResp != nil {
						io.Copy(io.Discard, altResp.Body)
						altResp.Body.Close()
					}
				}
			}
		}

		// 如果仍然失败，返回错误
		if err != nil {
			stdlog.Printf("所有上游服务器都无法连接")
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(proxyErrorPage))
			return
		}
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	// 拷贝响应头
	for k, v := range resp.Header {
		// 跳过原始的内容长度头，因为我们可能会修改内容
		if k == "Content-Length" {
			continue
		}
		w.Header()[k] = v
	}

	// 获取内容类型
	contentType := resp.Header.Get("Content-Type")

	// 处理响应体
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		stdlog.Printf("读取响应体失败: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var finalBody []byte
	var shouldCache = false

	// 处理防开发者工具注入
	if EnableAntiDevTools && isHTMLContent(contentType) && resp.StatusCode == 200 {
		modifiedBody := injectAntiDevTools(string(bodyBytes))
		finalBody = []byte(modifiedBody)
		shouldCache = true
	} else {
		finalBody = bodyBytes
		// 检查是否为可缓存的静态文件
		if staticCacheConfig.Enable && req.Method == "GET" && resp.StatusCode == 200 {
			if isCacheableStaticFile(req.URL.Path) {
				shouldCache = true
			}
		}
	}

	// 更新 Content-Length
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(finalBody)))

	// 缓存处理
	if shouldCache && staticCacheConfig.Enable {
		cacheKey := siteDomain + req.URL.Path
		addToCache(cacheKey, finalBody, contentType)
		w.Header().Set("X-Cache", "MISS")
		w.Header().Set("X-Cache-Key", cacheKey)
		stdlog.Printf("缓存添加: %s%s", host, req.URL.Path)
	} else {
		w.Header().Set("X-Cache", "BYPASS")
	}

	// 设置状态码并写入响应
	w.WriteHeader(resp.StatusCode)
	_, err = w.Write(finalBody)
	if err != nil {
		stdlog.Printf("写入响应失败: %v", err)
	}

	// 记录流量统计
	domain = siteDomain
	path = req.URL.Path
	statusCode = resp.StatusCode
	requestSize = req.ContentLength
	if requestSize <= 0 {
		requestSize = int64(len(requestBody))
	}
	responseSize = int64(len(finalBody))
	cacheStatus = w.Header().Get("X-Cache")
	if cacheStatus == "" {
		cacheStatus = "BYPASS"
	}

	clientIPAddr := getClientIP(req)
	userAgent := req.Header.Get("User-Agent")
	referer := req.Header.Get("Referer")
	responseTime := time.Since(startTime).Milliseconds()

	logTraffic(domain, path, req.Method, statusCode, clientIPAddr, userAgent, referer,
		requestSize, responseSize, responseTime, cacheStatus)
	trafficRecorded = true
}

// ------------------- 缓存管理 API -------------------
type CacheStatsResponse struct {
	Enable      bool   `json:"enable"`
	CacheHits   uint64 `json:"cache_hits"`
	CachedFiles int    `json:"cached_files"`
	CurrentSize string `json:"current_size"`
	MaxSize     string `json:"max_size"` // 确保有这个字段
}

type CacheConfigRequest struct {
	Enable    *bool `json:"enable"`
	MaxSizeMB *int  `json:"max_size_mb"`
}

// 获取缓存统计
func getCacheStatsHandler(c *gin.Context) {
	cacheMutex.RLock()
	cachedFiles := len(fileCache)
	currentSize := currentCacheSize
	cacheMutex.RUnlock()

	hits := atomic.LoadUint64(&cacheHits)

	stats := CacheStatsResponse{
		Enable:      staticCacheConfig.Enable,
		CacheHits:   hits,
		CachedFiles: cachedFiles,
		CurrentSize: fmt.Sprintf("%.2f MB", float64(currentSize)/(1024*1024)),
		MaxSize:     fmt.Sprintf("%.2f MB", float64(staticCacheConfig.MaxCacheSize)/(1024*1024)),
	}

	c.JSON(http.StatusOK, stats)
}

// ------------------- 缓存文件信息结构 -------------------
type CacheFileInfo struct {
	Key          string `json:"key"`
	Size         string `json:"size"`
	ContentType  string `json:"content_type"`
	LastModified string `json:"last_modified"`
	ExpireAt     string `json:"expire_at"`
	Site         string `json:"site"` // 添加站点字段
}

type CacheFileContent struct {
	Key         string `json:"key"`
	Content     string `json:"content"`
	ContentType string `json:"content_type"`
	Size        string `json:"size"`
}

// ------------------- 获取缓存文件列表接口 -------------------
func getCacheFilesHandler(c *gin.Context) {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	// 获取查询参数
	siteFilter := c.Query("site")                 // 站点筛选
	page := c.DefaultQuery("page", "1")           // 页码，默认1
	pageSize := c.DefaultQuery("page_size", "10") // 每页大小，默认10

	pageNum, _ := strconv.Atoi(page)
	pageSizeNum, _ := strconv.Atoi(pageSize)
	if pageNum < 1 {
		pageNum = 1
	}
	if pageSizeNum < 1 || pageSizeNum > 100 {
		pageSizeNum = 10
	}

	var files []CacheFileInfo
	siteMap := make(map[string]bool)

	for key, cachedFile := range fileCache {
		// 从key中提取站点信息（格式为 "domain/path"）
		site := "unknown"
		if strings.Contains(key, "/") {
			parts := strings.SplitN(key, "/", 2)
			if len(parts) > 0 {
				site = parts[0]
			}
		}
		siteMap[site] = true

		// 如果指定了站点筛选
		if siteFilter != "" && siteFilter != "all" {
			if site != siteFilter {
				continue
			}
		}

		fileInfo := CacheFileInfo{
			Key:          key,
			Size:         fmt.Sprintf("%.2f KB", float64(cachedFile.Size)/1024),
			ContentType:  cachedFile.ContentType,
			LastModified: cachedFile.LastModified.Format("2006-01-02 15:04:05"),
			ExpireAt:     cachedFile.ExpireAt.Format("2006-01-02 15:04:05"),
			Site:         site,
		}
		files = append(files, fileInfo)
	}

	// 按最后修改时间排序
	sort.Slice(files, func(i, j int) bool {
		return fileCache[files[i].Key].LastModified.After(fileCache[files[j].Key].LastModified)
	})

	// 分页处理
	total := len(files)
	start := (pageNum - 1) * pageSizeNum
	end := start + pageSizeNum
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	var pagedFiles []CacheFileInfo
	if start < end {
		pagedFiles = files[start:end]
	}

	// 获取所有唯一的站点列表
	sites := make([]string, 0, len(siteMap))
	for site := range siteMap {
		sites = append(sites, site)
	}
	sort.Strings(sites)

	c.JSON(http.StatusOK, gin.H{
		"files":     pagedFiles,
		"total":     total,
		"page":      pageNum,
		"page_size": pageSizeNum,
		"sites":     sites, // 返回可用站点列表
	})
}

var request struct {
	File string `json:"file" binding:"required"`
}

// ------------------- 获取缓存文件内容接口 -------------------
func getCacheFileContentHandler(c *gin.Context) {

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "无效的请求参数",
			"details": err.Error(),
		})
		return
	}

	cacheKey := request.File

	cacheMutex.RLock()
	cachedFile, exists := fileCache[cacheKey]
	cacheMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "缓存文件不存在"})
		return
	}

	var content string
	// 根据内容类型决定如何显示
	if isTextContent(cachedFile.ContentType) {
		content = string(cachedFile.Content)
	} else {
		// 对于二进制文件，显示为Base64或简单提示
		content = fmt.Sprintf("[二进制文件，大小: %.2f KB]", float64(cachedFile.Size)/1024)
	}

	response := CacheFileContent{
		Key:         cacheKey,
		Content:     content,
		ContentType: cachedFile.ContentType,
		Size:        fmt.Sprintf("%.2f KB", float64(cachedFile.Size)/1024),
	}

	c.JSON(http.StatusOK, response)
}

// 检查是否为文本内容
func isTextContent(contentType string) bool {
	textTypes := []string{
		"text/", "application/json", "application/javascript",
		"application/xml", "application/xhtml+xml",
	}

	for _, textType := range textTypes {
		if strings.Contains(contentType, textType) {
			return true
		}
	}
	return false
}

// 更新缓存配置
func updateCacheConfigHandler(c *gin.Context) {
	var req CacheConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Enable != nil {
		staticCacheConfig.Enable = *req.Enable
		if staticCacheConfig.Enable {
			initStaticCache()
		}
	}

	if req.MaxSizeMB != nil {
		staticCacheConfig.MaxCacheSize = int64(*req.MaxSizeMB) * 1024 * 1024
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     "缓存配置更新成功",
		"enable":      staticCacheConfig.Enable,
		"max_size_mb": staticCacheConfig.MaxCacheSize / (1024 * 1024),
	})
}

// 清空缓存
func clearCacheHandler(c *gin.Context) {
	cacheMutex.Lock()
	fileCache = make(map[string]*CachedFile)
	currentCacheSize = 0
	cacheMutex.Unlock()

	atomic.StoreUint64(&cacheHits, 0)
	atomic.StoreUint64(&cacheMisses, 0)

	c.JSON(http.StatusOK, gin.H{"message": "缓存已清空"})
}

// ------------------ACL------------------
type ACLRule struct {
	ID          int    `json:"id"`
	Type        string `json:"type"`      // "global" 或 "host"
	Host        string `json:"host"`      // 对于 host 类型有效
	RuleType    string `json:"rule_type"` // "ip", "country", "user_agent", "referer", "path"
	Pattern     string `json:"pattern"`
	Action      string `json:"action"` // "allow" 或 "block"
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}
type ACLManager struct {
	rules      []ACLRule
	ipRules    map[string][]ACLRule // IP 规则缓存
	regexCache map[string]*regexp.Regexp
	mutex      sync.RWMutex
}

var aclManager *ACLManager

func initACL() {
	aclManager = &ACLManager{
		rules:      make([]ACLRule, 0),
		ipRules:    make(map[string][]ACLRule),
		regexCache: make(map[string]*regexp.Regexp),
	}

	// 从数据库加载 ACL 规则
	loadACLRulesFromDB()
}

// ------------------- 更新站点状态请求 -------------------
type UpdateSiteStatusRequest struct {
	ID     int `json:"id" binding:"required"`
	Status int `json:"status" binding:"oneof=0 1"` // 移除 required
}

// ------------------- 更新站点状态接口 -------------------
func updateSiteStatusHandler(c *gin.Context) {
	var req UpdateSiteStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 更新数据库
	_, err := db.Exec("UPDATE sites SET status = ? WHERE id = ?", req.Status, req.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("更新站点状态失败: %v", err)})
		return
	}

	// 热更新内存 sites 列表
	aclManager.mutex.Lock()
	for i, site := range sites {
		if site.ID == req.ID {
			sites[i].Status = req.Status

			// 如果站点被禁用且启用了HTTPS，从证书映射中移除
			if req.Status == 0 && site.EnableHTTPS {
				delete(certificateMap, site.Domain)
				stdlog.Printf("站点禁用，已移除证书映射: %s", site.Domain)
			}

			// 如果站点被重新启用且启用了HTTPS，重新加载证书
			if req.Status == 1 && site.EnableHTTPS && site.CERTID.Valid {
				// 重新加载证书
				err := reloadSiteCertificate(site.ID)
				if err != nil {
					stdlog.Printf("重新加载站点证书失败: %v", err)
				}
			}
			break
		}
	}
	aclManager.mutex.Unlock()

	statusText := "启用"
	if req.Status == 0 {
		statusText = "禁用"
	}

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("站点%s成功", statusText),
		"status":  req.Status,
	})
}

// 重新加载单个站点的证书
func reloadSiteCertificate(siteID int) error {
	query := `
        SELECT s.domain, c.cert_text, c.key_text 
        FROM sites s 
        JOIN certificates c ON s.cert_id = c.id 
        WHERE s.id = ? AND s.enable_https = 1 AND s.status = 1
    `

	var domain, certText, keyText string
	err := db.QueryRow(query, siteID).Scan(&domain, &certText, &keyText)
	if err != nil {
		return fmt.Errorf("查询站点证书失败: %v", err)
	}

	// 加载证书
	cert, err := tls.X509KeyPair([]byte(certText), []byte(keyText))
	if err != nil {
		return fmt.Errorf("加载证书失败: %v", err)
	}

	certificateMap[domain] = cert
	stdlog.Printf("站点证书重新加载: %s", domain)
	return nil
}

// ------------------- 更新站点HTTPS状态请求 -------------------
type UpdateSiteHTTPSRequest struct {
	ID          int  `json:"id" binding:"required"`
	EnableHTTPS bool `json:"enable_https"`
	CertID      *int `json:"cert_id,omitempty"` // 可选，切换HTTPS时指定证书
}

// ------------------- 更新站点HTTPS状态接口 -------------------
func updateSiteHTTPSHandler(c *gin.Context) {
	var req UpdateSiteHTTPSRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 查询站点当前信息
	var currentDomain string
	var currentStatus int
	err := db.QueryRow("SELECT domain, status FROM sites WHERE id = ?", req.ID).Scan(&currentDomain, &currentStatus)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "站点不存在"})
		return
	}

	// 如果启用HTTPS但没有提供证书ID，检查是否已有证书
	if req.EnableHTTPS && req.CertID == nil {
		var existingCertID sql.NullInt64
		err := db.QueryRow("SELECT cert_id, domain FROM sites WHERE id = ?", req.ID).Scan(&existingCertID, &currentDomain)
		if err != nil || !existingCertID.Valid {
			// 自动生成自签名证书
			stdlog.Printf("站点 %s 启用HTTPS但无证书，自动生成自签名证书", currentDomain)
			certPEM, keyPEM, err := generateSelfSignedCert(currentDomain)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("自动生成证书失败: %v", err)})
				return
			}

			// 插入证书到数据库
			insertCert := `INSERT INTO certificates (name, cert_text, key_text) VALUES (?, ?, ?)`
			result, err := db.Exec(insertCert, currentDomain+"自动生成证书", certPEM, keyPEM)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("保存自动生成证书失败: %v", err)})
				return
			}

			certID, _ := result.LastInsertId()
			certIDInt := int(certID)
			req.CertID = &certIDInt

			// 热加载证书到内存
			cert, err := tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				stdlog.Printf("加载自动生成证书失败: %v", err)
			} else {
				certificateMap[currentDomain] = cert
				stdlog.Printf("自动生成证书已加载: %s", currentDomain)
			}
		} else {
			certIDVal := int(existingCertID.Int64)
			req.CertID = &certIDVal
		}
	}

	// 如果启用HTTPS且有证书ID，验证证书是否存在
	if req.EnableHTTPS && req.CertID != nil {
		var certCount int
		err := db.QueryRow("SELECT COUNT(*) FROM certificates WHERE id = ?", *req.CertID).Scan(&certCount)
		if err != nil || certCount == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "指定的证书不存在"})
			return
		}
	}

	// 更新数据库
	var result sql.Result
	if req.EnableHTTPS {
		// 启用HTTPS
		result, err = db.Exec(
			"UPDATE sites SET enable_https = 1, cert_id = ? WHERE id = ?",
			req.CertID, req.ID,
		)
	} else {
		// 禁用HTTPS
		result, err = db.Exec(
			"UPDATE sites SET enable_https = 0 WHERE id = ?",
			req.ID,
		)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("更新HTTPS状态失败: %v", err)})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "站点不存在或状态未改变"})
		return
	}

	// 热更新内存 sites 列表和证书映射
	aclManager.mutex.Lock()
	for i, site := range sites {
		if site.ID == req.ID {
			sites[i].EnableHTTPS = req.EnableHTTPS
			if req.EnableHTTPS && req.CertID != nil {
				sites[i].CERTID = sql.NullInt64{Int64: int64(*req.CertID), Valid: true}

				// 加载证书到内存
				err := reloadSiteCertificate(site.ID)
				if err != nil {
					stdlog.Printf("加载证书失败: %v", err)
				}
			} else {
				sites[i].CERTID = sql.NullInt64{Valid: false}
				// 从证书映射中移除
				delete(certificateMap, site.Domain)
				stdlog.Printf("HTTPS已禁用，移除证书映射: %s", site.Domain)
			}
			break
		}
	}
	aclManager.mutex.Unlock()

	httpsStatus := "启用"
	if !req.EnableHTTPS {
		httpsStatus = "禁用"
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      fmt.Sprintf("站点HTTPS%s成功", httpsStatus),
		"enable_https": req.EnableHTTPS,
	})
}

func loadACLRulesFromDB() {
	aclManager.mutex.Lock()
	defer aclManager.mutex.Unlock()

	query := `
        SELECT id, type, host, rule_type, pattern, action, description, enabled 
        FROM acl_rules 
        WHERE enabled = 1
        ORDER BY type DESC, id ASC
    `

	rows, err := db.Query(query)
	if err != nil {
		// 如果表不存在，创建表
		if strings.Contains(err.Error(), "no such table") {
			createACLTable()
			return
		}
		stdlog.Printf("加载 ACL 规则失败: %v", err)
		return
	}
	defer rows.Close()

	aclManager.rules = make([]ACLRule, 0)
	aclManager.ipRules = make(map[string][]ACLRule)

	for rows.Next() {
		var rule ACLRule
		err := rows.Scan(
			&rule.ID, &rule.Type, &rule.Host, &rule.RuleType,
			&rule.Pattern, &rule.Action, &rule.Description, &rule.Enabled,
		)
		if err != nil {
			stdlog.Printf("读取 ACL 规则失败: %v", err)
			continue
		}
		aclManager.rules = append(aclManager.rules, rule)

		// 缓存 IP 规则以便快速查找
		if rule.RuleType == "ip" {
			aclManager.ipRules[rule.Pattern] = append(aclManager.ipRules[rule.Pattern], rule)
		}
	}

	stdlog.Printf("加载了 %d 条 ACL 规则", len(aclManager.rules))
}

func createACLTable() {
	createTable := `
        CREATE TABLE IF NOT EXISTS acl_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL DEFAULT 'global',
            host TEXT DEFAULT NULL,
            rule_type TEXT NOT NULL,
            pattern TEXT NOT NULL,
            action TEXT NOT NULL,
            description TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `

	_, err := db.Exec(createTable)
	if err != nil {
		stdlog.Printf("创建 ACL 表失败: %v", err)
		return
	}

	// 插入一些默认规则
	insertDefaultRules()
}

// ------------------- 创建流量统计表 -------------------
func createTrafficTable() {
	createTable := `
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            path TEXT NOT NULL,
            method TEXT NOT NULL,
            status_code INTEGER NOT NULL,
            client_ip TEXT NOT NULL,
            user_agent TEXT DEFAULT '',
            referer TEXT DEFAULT '',
            request_size INTEGER DEFAULT 0,
            response_size INTEGER DEFAULT 0,
            response_time INTEGER DEFAULT 0,
            cache_status TEXT DEFAULT 'BYPASS',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `

	_, err := db.Exec(createTable)
	if err != nil {
		stdlog.Printf("创建流量统计表失败: %v", err)
		return
	}

	// 创建索引以提高查询性能
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_traffic_domain ON traffic_logs(domain)")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_traffic_created_at ON traffic_logs(created_at)")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_traffic_client_ip ON traffic_logs(client_ip)")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_traffic_status_code ON traffic_logs(status_code)")

	stdlog.Printf("流量统计表创建成功")
}

// ------------------- 流量记录通道 -------------------
var trafficChan = make(chan TrafficLog, 10000)

// ------------------- 记录流量 -------------------
func logTraffic(domain, path, method string, statusCode int, clientIP, userAgent, referer string, requestSize, responseSize int64, responseTime int64, cacheStatus string) {
	// 异步记录，避免阻塞主流程
	trafficLog := TrafficLog{
		Domain:       domain,
		Path:         path,
		Method:       method,
		StatusCode:   statusCode,
		ClientIP:     clientIP,
		UserAgent:    userAgent,
		Referer:      referer,
		RequestSize:  requestSize,
		ResponseSize: responseSize,
		ResponseTime: responseTime,
		CacheStatus:  cacheStatus,
		CreatedAt:    time.Now(),
	}

	select {
	case trafficChan <- trafficLog:
		// 成功发送
	default:
		// 通道已满，跳过本次记录（避免阻塞）
		stdlog.Printf("流量记录通道已满，跳过记录")
	}
}

// ------------------- 流量记录工作器 -------------------
func trafficLogWorker() {
	for log := range trafficChan {
		query := `
            INSERT INTO traffic_logs (domain, path, method, status_code, client_ip, user_agent, referer, 
                                     request_size, response_size, response_time, cache_status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `
		_, err := db.Exec(query,
			log.Domain, log.Path, log.Method, log.StatusCode, log.ClientIP, log.UserAgent, log.Referer,
			log.RequestSize, log.ResponseSize, log.ResponseTime, log.CacheStatus, log.CreatedAt)
		if err != nil {
			stdlog.Printf("记录流量日志失败: %v", err)
		}
	}
}

func insertDefaultRules() {
	defaultRules := []ACLRule{
		{
			Type:        "global",
			RuleType:    "ip",
			Pattern:     "192.168.150.1",
			Action:      "block",
			Description: "阻止特定内部 IP",
			Enabled:     true,
		},
		{
			Type:        "global",
			RuleType:    "path",
			Pattern:     "^/admin",
			Action:      "block",
			Description: "阻止访问 admin 路径",
			Enabled:     true,
		},
		{
			Type:        "host",
			Host:        "kabubu.com",
			RuleType:    "user_agent",
			Pattern:     "(?i)bot|crawler|spider",
			Action:      "block",
			Description: "阻止爬虫访问 kabubu.com",
			Enabled:     true,
		},
	}

	insertQuery := `
        INSERT INTO acl_rules (type, host, rule_type, pattern, action, description, enabled)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `

	for _, rule := range defaultRules {
		_, err := db.Exec(
			insertQuery,
			rule.Type, rule.Host, rule.RuleType, rule.Pattern,
			rule.Action, rule.Description, rule.Enabled,
		)
		if err != nil {
			stdlog.Printf("插入默认 ACL 规则失败: %v", err)
		}
	}

	stdlog.Println("ACL 默认规则已插入")
}

// ------------------- ACL 匹配逻辑 -------------------
func (a *ACLManager) checkACL(req *http.Request, host string) (bool, *ACLRule) {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	clientIP := getClientIP(req)
	userAgent := req.UserAgent()
	referer := req.Referer()
	path := req.URL.Path

	// 先检查全局规则，再检查 host 特定规则
	ruleSets := [][]ACLRule{
		a.getRulesByType("global", ""),
		a.getRulesByType("host", host),
	}

	for _, rules := range ruleSets {
		for _, rule := range rules {
			if a.matchRule(rule, clientIP, userAgent, referer, path) {
				return rule.Action == "block", &rule
			}
		}
	}

	return false, nil
}
func (a *ACLManager) getRulesByType(ruleType, host string) []ACLRule {
	var result []ACLRule
	for _, rule := range a.rules {
		if rule.Type == ruleType {
			if ruleType == "global" || (ruleType == "host" && rule.Host == host) {
				result = append(result, rule)
			}
		}
	}
	return result
}

func (a *ACLManager) matchRule(rule ACLRule, ip, userAgent, referer, path string) bool {
	switch rule.RuleType {
	case "ip":
		return a.matchIP(ip, rule.Pattern)
	case "user_agent":
		return a.matchRegex(userAgent, rule.Pattern)
	case "referer":
		return a.matchRegex(referer, rule.Pattern)
	case "path":
		return a.matchRegex(path, rule.Pattern)
	case "country":
		// 这里可以集成 IP 地理定位库
		return false
	}
	return false
}

func (a *ACLManager) matchIP(clientIP, pattern string) bool {
	if pattern == clientIP {
		return true
	}

	// 支持 CIDR 格式
	if strings.Contains(pattern, "/") {
		_, ipNet, err := net.ParseCIDR(pattern)
		if err == nil {
			return ipNet.Contains(net.ParseIP(clientIP))
		}
	}

	// 支持通配符
	if strings.Contains(pattern, "*") {
		regexPattern := strings.ReplaceAll(regexp.QuoteMeta(pattern), "\\*", ".*")
		return a.matchRegex(clientIP, regexPattern)
	}

	return false
}

func (a *ACLManager) matchRegex(text, pattern string) bool {
	if text == "" {
		return false
	}

	// 检查缓存
	if re, exists := a.regexCache[pattern]; exists {
		return re.MatchString(text)
	}

	// 编译新正则
	re, err := regexp.Compile(pattern)
	if err != nil {
		stdlog.Printf("ACL 正则编译失败: %s, 错误: %v", pattern, err)
		return false
	}

	a.regexCache[pattern] = re
	return re.MatchString(text)
}

// ------------------- 工具函数 -------------------
func getClientIP(req *http.Request) string {
	// 检查 X-Forwarded-For
	if forwarded := req.Header.Get("X-Forwarded-For"); forwarded != "" {
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// 检查 X-Real-IP
	if realIP := req.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	// 使用 RemoteAddr
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

// ------------------- ACL API 接口 -------------------
type AddACLRuleRequest struct {
	Type        string `json:"type" binding:"required"`
	Host        string `json:"host"`
	RuleType    string `json:"rule_type" binding:"required"`
	Pattern     string `json:"pattern" binding:"required"`
	Action      string `json:"action" binding:"required"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

func addACLRuleHandler(c *gin.Context) {
	var req AddACLRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 验证参数
	if req.Type != "global" && req.Type != "host" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "type 必须是 global 或 host"})
		return
	}

	if req.Action != "allow" && req.Action != "block" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action 必须是 allow 或 block"})
		return
	}

	if req.Type == "host" && req.Host == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "host 类型必须指定 host"})
		return
	}

	// 插入数据库
	query := `
        INSERT INTO acl_rules (type, host, rule_type, pattern, action, description, enabled)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `

	result, err := db.Exec(
		query,
		req.Type, req.Host, req.RuleType, req.Pattern,
		req.Action, req.Description, req.Enabled,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("插入规则失败: %v", err)})
		return
	}

	id, _ := result.LastInsertId()

	// 热更新内存规则
	aclManager.mutex.Lock()
	newRule := ACLRule{
		ID:          int(id),
		Type:        req.Type,
		Host:        req.Host,
		RuleType:    req.RuleType,
		Pattern:     req.Pattern,
		Action:      req.Action,
		Description: req.Description,
		Enabled:     req.Enabled,
	}
	aclManager.rules = append(aclManager.rules, newRule)

	// 更新 IP 规则缓存
	if newRule.RuleType == "ip" {
		aclManager.ipRules[newRule.Pattern] = append(aclManager.ipRules[newRule.Pattern], newRule)
	}
	aclManager.mutex.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"message": "ACL 规则添加成功",
		"id":      id,
	})
}

func getACLRulesHandler(c *gin.Context) {
	// 从数据库加载所有规则（包括禁用的），用于管理界面显示
	query := `
        SELECT id, type, host, rule_type, pattern, action, description, enabled 
        FROM acl_rules 
        ORDER BY type DESC, id ASC
    `

	rows, err := db.Query(query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("查询规则失败: %v", err)})
		return
	}
	defer rows.Close()

	rules := make([]ACLRule, 0)
	for rows.Next() {
		var rule ACLRule
		err := rows.Scan(
			&rule.ID, &rule.Type, &rule.Host, &rule.RuleType,
			&rule.Pattern, &rule.Action, &rule.Description, &rule.Enabled,
		)
		if err != nil {
			stdlog.Printf("读取 ACL 规则失败: %v", err)
			continue
		}
		rules = append(rules, rule)
	}

	c.JSON(http.StatusOK, gin.H{
		"rules": rules,
		"count": len(rules),
	})
}

func deleteACLRuleHandler(c *gin.Context) {
	id := c.Param("id")

	_, err := db.Exec("DELETE FROM acl_rules WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("删除规则失败: %v", err)})
		return
	}

	// 热更新内存规则
	aclManager.mutex.Lock()
	for i, rule := range aclManager.rules {
		if fmt.Sprintf("%d", rule.ID) == id {
			aclManager.rules = append(aclManager.rules[:i], aclManager.rules[i+1:]...)
			break
		}
	}

	// 清理 IP 规则缓存
	for pattern, rules := range aclManager.ipRules {
		newRules := make([]ACLRule, 0)
		for _, rule := range rules {
			if fmt.Sprintf("%d", rule.ID) != id {
				newRules = append(newRules, rule)
			}
		}
		aclManager.ipRules[pattern] = newRules
	}
	aclManager.mutex.Unlock()

	c.JSON(http.StatusOK, gin.H{"message": "规则删除成功"})
}

func toggleACLRuleHandler(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Enabled bool `json:"enabled"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 先从数据库查询规则信息
	var rule ACLRule
	query := `SELECT id, type, host, rule_type, pattern, action, description, enabled FROM acl_rules WHERE id = ?`
	err := db.QueryRow(query, id).Scan(
		&rule.ID, &rule.Type, &rule.Host, &rule.RuleType,
		&rule.Pattern, &rule.Action, &rule.Description, &rule.Enabled,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "规则不存在"})
		return
	}

	// 更新数据库
	_, err = db.Exec("UPDATE acl_rules SET enabled = ? WHERE id = ?", req.Enabled, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("更新规则状态失败: %v", err)})
		return
	}

	// 更新规则状态
	rule.Enabled = req.Enabled

	// 热更新内存规则
	aclManager.mutex.Lock()

	if req.Enabled {
		// 启用规则：添加到内存中
		found := false
		for i, r := range aclManager.rules {
			if fmt.Sprintf("%d", r.ID) == id {
				// 如果已存在，更新它
				aclManager.rules[i] = rule
				found = true
				break
			}
		}
		if !found {
			// 如果不存在，添加它
			aclManager.rules = append(aclManager.rules, rule)
		}

		// 如果是IP规则，更新IP规则缓存
		if rule.RuleType == "ip" {
			found := false
			for _, r := range aclManager.ipRules[rule.Pattern] {
				if fmt.Sprintf("%d", r.ID) == id {
					found = true
					break
				}
			}
			if !found {
				aclManager.ipRules[rule.Pattern] = append(aclManager.ipRules[rule.Pattern], rule)
			}
		}
	} else {
		// 禁用规则：从内存中移除
		for i, r := range aclManager.rules {
			if fmt.Sprintf("%d", r.ID) == id {
				aclManager.rules = append(aclManager.rules[:i], aclManager.rules[i+1:]...)
				break
			}
		}

		// 从IP规则缓存中移除
		if rule.RuleType == "ip" {
			newRules := make([]ACLRule, 0)
			for _, r := range aclManager.ipRules[rule.Pattern] {
				if fmt.Sprintf("%d", r.ID) != id {
					newRules = append(newRules, r)
				}
			}
			if len(newRules) > 0 {
				aclManager.ipRules[rule.Pattern] = newRules
			} else {
				delete(aclManager.ipRules, rule.Pattern)
			}
		}
	}

	aclManager.mutex.Unlock()

	status := "启用"
	if !req.Enabled {
		status = "禁用"
	}

	stdlog.Printf("ACL规则%s: ID %s", status, id)

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("规则%s成功", status),
		"enabled": req.Enabled,
	})
}

// ------------------- 修改主处理函数 -------------------

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
			stdlog.Printf("加载证书失败: %v", err)
		} else {
			certificateMap[req.Domain] = cert
			stdlog.Printf("新证书已加载: %s", req.Domain)
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
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, string(loginError))
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

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, string(panle))
}

// 认证中间件
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取cookie中的token
		tokenString, err := c.Cookie("auth_token")
		if err != nil {
			// 没有token，重定向到登录页面
			c.Header("Content-Type", "text/html; charset=utf-8")
			c.String(http.StatusOK, string(login))
			c.Abort()
			return
		}

		// 解析和验证token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// 验证签名方法
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jsonTokenKey, nil
		})

		if err != nil || !token.Valid {
			// token无效，重定向到登录页面
			c.Header("Content-Type", "text/html; charset=utf-8")
			c.String(http.StatusOK, string(login))
			c.Abort()
			return
		}

		// token验证通过，继续处理请求
		c.Next()
	}
}

// ------------------- 统计数据结构 -------------------
type StatsResponse struct {
	TotalRequests   uint64 `json:"total_requests"`
	BlockedRequests uint64 `json:"blocked_requests"`
	CacheHitRate    string `json:"cache_hit_rate"`
	TotalRules      int    `json:"total_rules"`
	TotalSites      int    `json:"total_sites"`
}

// ------------------- 获取统计数据的API -------------------
func getStatsHandler(c *gin.Context) {
	// 计算缓存命中率
	hits := atomic.LoadUint64(&cacheHits)
	misses := atomic.LoadUint64(&cacheMisses)
	total := hits + misses
	hitRate := "0%"
	if total > 0 {
		hitRate = fmt.Sprintf("%.2f%%", float64(hits)/float64(total)*100)
	}

	// 计算总规则数
	totalRules := 0
	for _, rules := range RULES {
		totalRules += len(rules)
	}

	stats := StatsResponse{
		TotalRequests:   atomic.LoadUint64(&totalRequests),
		BlockedRequests: atomic.LoadUint64(&totalBlocked),
		CacheHitRate:    hitRate,
		TotalRules:      totalRules,
		TotalSites:      len(sites),
	}

	c.JSON(http.StatusOK, stats)
}

// ------------------- 站点信息响应结构 -------------------
type SiteInfoResponse struct {
	ID                   int                  `json:"id"`
	Name                 string               `json:"name"`
	Domain               string               `json:"domain"`
	TargetURL            string               `json:"target_url"`
	EnableHTTPS          bool                 `json:"enable_https"`
	CertID               *int                 `json:"cert_id,omitempty"`
	Status               int                  `json:"status"`
	LoadBalanceAlgorithm string               `json:"load_balance_algorithm"`
	UpstreamServers      []UpstreamServerInfo `json:"upstream_servers"`
	CreatedAt            string               `json:"created_at"`
	UpdatedAt            string               `json:"updated_at"`
}

type UpstreamServerInfo struct {
	ID     int    `json:"id"`
	URL    string `json:"url"`
	Weight int    `json:"weight"`
	Status int    `json:"status"`
}

// ------------------- 删除站点请求 -------------------
type DeleteSiteRequest struct {
	ID int `json:"id" binding:"required"`
}

// ------------------- 上传证书请求 -------------------
type UploadCertRequest struct {
	Name     string `json:"name" binding:"required"`
	CertText string `json:"cert_text" binding:"required"`
	KeyText  string `json:"key_text" binding:"required"`
}

// ------------------- 获取站点信息接口 -------------------
func getSitesHandler(c *gin.Context) {
	aclManager.mutex.RLock()
	defer aclManager.mutex.RUnlock()

	var sitesResponse []SiteInfoResponse
	for _, site := range sites {
		var certID *int
		if site.CERTID.Valid {
			certIDValue := int(site.CERTID.Int64)
			certID = &certIDValue
		}

		// 构建上游服务器信息
		upstreamServers := make([]UpstreamServerInfo, 0)
		for _, us := range site.UpstreamServers {
			upstreamServers = append(upstreamServers, UpstreamServerInfo{
				ID:     us.ID,
				URL:    us.URL,
				Weight: us.Weight,
				Status: us.Status,
			})
		}

		sitesResponse = append(sitesResponse, SiteInfoResponse{
			ID:                   site.ID,
			Name:                 site.Name,
			Domain:               site.Domain,
			TargetURL:            site.TargetURL,
			EnableHTTPS:          site.EnableHTTPS,
			CertID:               certID,
			Status:               site.Status,
			LoadBalanceAlgorithm: site.LoadBalanceAlgorithm,
			UpstreamServers:      upstreamServers,
			CreatedAt:            site.CreatedAt,
			UpdatedAt:            site.UpdatedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"sites": sitesResponse,
		"count": len(sitesResponse),
	})
}

// ------------------- 更新站点请求 -------------------
type UpdateSiteRequest struct {
	ID                   int                 `json:"id" binding:"required"`
	Name                 string              `json:"name" binding:"required"`
	Domain               string              `json:"domain" binding:"required"`
	TargetURL            string              `json:"target_url"`
	LoadBalanceAlgorithm string              `json:"load_balance_algorithm"`
	UpstreamServers      []UpstreamServerAdd `json:"upstream_servers"`
}

// ------------------- 更新站点接口 -------------------
func updateSiteHandler(c *gin.Context) {
	var req map[string]interface{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 手动提取和转换字段
	updateReq := UpdateSiteRequest{
		ID:                   int(getFloat64(req, "id")),
		Name:                 getString(req, "name"),
		Domain:               getString(req, "domain"),
		TargetURL:            getString(req, "target_url"),
		LoadBalanceAlgorithm: getString(req, "load_balance_algorithm"),
	}

	// 处理上游服务器
	if upstreamServersData, exists := req["upstream_servers"]; exists {
		if upstreamList, ok := upstreamServersData.([]interface{}); ok {
			for _, us := range upstreamList {
				if usMap, ok := us.(map[string]interface{}); ok {
					updateReq.UpstreamServers = append(updateReq.UpstreamServers, UpstreamServerAdd{
						URL:    getString(usMap, "url"),
						Weight: getInt(usMap, "weight"),
					})
				}
			}
		}
	}

	// 验证必需字段
	if updateReq.ID == 0 || updateReq.Name == "" || updateReq.Domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id, name, domain 为必填字段"})
		return
	}

	// 如果未启用负载均衡，target_url是必需的
	if updateReq.LoadBalanceAlgorithm == "" && updateReq.TargetURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未启用负载均衡时，target_url 为必填字段"})
		return
	}

	// 如果启用了负载均衡，必须有上游服务器
	if updateReq.LoadBalanceAlgorithm != "" && len(updateReq.UpstreamServers) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "启用负载均衡时，必须至少配置一个上游服务器"})
		return
	}

	// 获取原有站点信息，用于检查域名变更
	var oldDomain string
	err := db.QueryRow("SELECT domain FROM sites WHERE id = ?", updateReq.ID).Scan(&oldDomain)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "站点不存在"})
		return
	}

	// 确定target_url
	targetURL := updateReq.TargetURL
	if targetURL == "" && len(updateReq.UpstreamServers) > 0 {
		targetURL = updateReq.UpstreamServers[0].URL
	}

	// 更新站点基本信息
	_, err = db.Exec("UPDATE sites SET name = ?, domain = ?, target_url = ?, load_balance_algorithm = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		updateReq.Name, updateReq.Domain, targetURL, updateReq.LoadBalanceAlgorithm, updateReq.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("更新站点失败: %v", err)})
		return
	}

	// 如果域名变更，更新证书映射
	if oldDomain != updateReq.Domain {
		aclManager.mutex.RLock()
		var oldCert tls.Certificate
		var hasOldCert bool
		if cert, exists := certificateMap[oldDomain]; exists {
			oldCert = cert
			hasOldCert = true
		}
		aclManager.mutex.RUnlock()

		if hasOldCert {
			aclManager.mutex.Lock()
			delete(certificateMap, oldDomain)
			certificateMap[updateReq.Domain] = oldCert
			aclManager.mutex.Unlock()
			stdlog.Printf("站点域名变更，更新证书映射: %s -> %s", oldDomain, updateReq.Domain)
		}
	}

	// 删除原有的上游服务器
	_, err = db.Exec("DELETE FROM upstream_servers WHERE site_id = ?", updateReq.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("删除上游服务器失败: %v", err)})
		return
	}

	// 插入新的上游服务器
	var upstreamServers []UpstreamServer
	if updateReq.LoadBalanceAlgorithm != "" && len(updateReq.UpstreamServers) > 0 {
		insertUpstream := `INSERT INTO upstream_servers (site_id, url, weight, status) VALUES (?, ?, ?, ?)`
		for _, us := range updateReq.UpstreamServers {
			if us.URL != "" {
				if us.Weight <= 0 {
					us.Weight = 1 // 默认权重为1
				}
				_, err := db.Exec(insertUpstream, updateReq.ID, us.URL, us.Weight, 1)
				if err == nil {
					upstreamServers = append(upstreamServers, UpstreamServer{
						SiteID: updateReq.ID,
						URL:    us.URL,
						Weight: us.Weight,
						Status: 1,
					})
				}
			}
		}
	}

	// 热更新内存 sites 列表
	aclManager.mutex.Lock()
	for i := range sites {
		if sites[i].ID == updateReq.ID {
			sites[i].Name = updateReq.Name
			sites[i].Domain = updateReq.Domain
			sites[i].TargetURL = targetURL
			sites[i].LoadBalanceAlgorithm = updateReq.LoadBalanceAlgorithm
			sites[i].UpstreamServers = upstreamServers
			sites[i].UpdatedAt = time.Now().Format("2006-01-02 15:04:05")
			break
		}
	}
	aclManager.mutex.Unlock()

	c.JSON(http.StatusOK, gin.H{"message": "站点更新成功"})
}

// ------------------- 删除站点接口 -------------------
func deleteSiteHandler(c *gin.Context) {
	var req DeleteSiteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 从数据库删除站点
	_, err := db.Exec("DELETE FROM sites WHERE id = ?", req.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("删除站点失败: %v", err)})
		return
	}

	// 热更新内存 sites 列表
	aclManager.mutex.Lock()
	for i, site := range sites {
		if site.ID == req.ID {
			// 如果站点启用了HTTPS，从证书映射中移除
			if site.EnableHTTPS {
				delete(certificateMap, site.Domain)
				stdlog.Printf("已移除证书映射: %s", site.Domain)
			}

			// 从slices中删除
			sites = append(sites[:i], sites[i+1:]...)
			break
		}
	}
	aclManager.mutex.Unlock()

	c.JSON(http.StatusOK, gin.H{"message": "站点删除成功"})
}

// ------------------- 上传证书接口 -------------------
func uploadCertHandler(c *gin.Context) {
	var req UploadCertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 验证证书格式
	_, err := tls.X509KeyPair([]byte(req.CertText), []byte(req.KeyText))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("证书格式无效: %v", err)})
		return
	}

	// 插入证书到数据库
	insertCert := `INSERT INTO certificates (name, cert_text, key_text) VALUES (?, ?, ?)`
	result, err := db.Exec(insertCert, req.Name, req.CertText, req.KeyText)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("保存证书失败: %v", err)})
		return
	}

	certID, _ := result.LastInsertId()

	// 热加载证书到内存（但不立即关联到任何站点）
	cert, err := tls.X509KeyPair([]byte(req.CertText), []byte(req.KeyText))
	if err != nil {
		stdlog.Printf("加载证书失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "证书加载失败"})
		return
	}

	// 这里不直接添加到certificateMap，因为证书需要关联到具体域名
	// 证书会在站点启用HTTPS时通过cert_id关联加载

	c.JSON(http.StatusOK, gin.H{
		"message": "证书上传成功",
		"cert_id": certID,
		"cert":    cert, // 这里只是返回确认，实际使用时可以移除
	})
}

// ------------------- 更新站点证书接口（辅助功能） -------------------
type UpdateSiteCertRequest struct {
	SiteID int `json:"site_id" binding:"required"`
	CertID int `json:"cert_id" binding:"required"`
}

type RuleStatusRequest struct {
	RuleID string `json:"rule_id" binding:"required"`
	Enable bool   `json:"enable"`
}

func removeFromSlice(slice []string, id string) []string {
	result := []string{}
	for _, v := range slice {
		if v != id {
			result = append(result, v)
		}
	}
	return result
}

// ------------------- 启用/禁用规则接口 -------------------
func updateRuleStatusHandler(c *gin.Context) {
	var req RuleStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	found := false
	for method, rules := range RULES {
		for i, rule := range rules {
			if rule.ID == req.RuleID {
				// 更新规则状态
				RULES[method][i].Enabled = req.Enable
				if req.Enable == false {
					blockedRuleId = append(blockedRuleId, rule.ID)
				} else {
					blockedRuleId = removeFromSlice(blockedRuleId, rule.ID)
				}
				found = true

				action := "启用"
				if !req.Enable {
					action = "禁用"
				}
				stdlog.Printf("规则状态更新: %s (%s) - %s", rule.Name, rule.ID, action)
				break
			}
		}
		if found {
			break
		}
	}

	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "规则不存在"})
		return
	}

	action := "启用"
	if !req.Enable {
		action = "禁用"
	}

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("规则%s成功", action),
		"rule_id": req.RuleID,
		"enabled": req.Enable,
	})
}

// ------------------- 重新加载规则接口 -------------------
func reloadRulesHandler(c *gin.Context) {
	// 保存当前的启用状态
	enabledStatus := make(map[string]bool)
	for _, rules := range RULES {
		for _, rule := range rules {
			enabledStatus[rule.ID] = rule.Enabled
		}
	}

	// 重新加载规则
	readRule()

	// 恢复之前的启用状态
	for method, rules := range RULES {
		for i, rule := range rules {
			if enabled, exists := enabledStatus[rule.ID]; exists {
				RULES[method][i].Enabled = enabled
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message":          "规则重新加载成功",
		"preserved_status": len(enabledStatus),
	})
}

func updateSiteCertHandler(c *gin.Context) {
	var req UpdateSiteCertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 查询站点和证书信息
	var domain, certText, keyText string
	query := `
        SELECT s.domain, c.cert_text, c.key_text 
        FROM sites s, certificates c 
        WHERE s.id = ? AND c.id = ? AND s.enable_https = 1
    `
	err := db.QueryRow(query, req.SiteID, req.CertID).Scan(&domain, &certText, &keyText)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "站点或证书不存在，或站点未启用HTTPS"})
		return
	}

	// 更新站点的证书ID
	_, err = db.Exec("UPDATE sites SET cert_id = ? WHERE id = ?", req.CertID, req.SiteID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("更新站点证书失败: %v", err)})
		return
	}

	// 热加载证书到内存
	cert, err := tls.X509KeyPair([]byte(certText), []byte(keyText))
	if err != nil {
		stdlog.Printf("加载证书失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "证书加载失败"})
		return
	}

	// 更新证书映射
	aclManager.mutex.Lock()
	certificateMap[domain] = cert
	aclManager.mutex.Unlock()

	stdlog.Printf("证书已热加载: %s", domain)

	c.JSON(http.StatusOK, gin.H{"message": "站点证书更新成功"})
}

// ------------------- 重新加载所有证书（用于初始化或手动刷新） -------------------
func reloadAllCertificatesHandler(c *gin.Context) {
	err := initCertificatesFromDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("重新加载证书失败: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":             "证书重新加载成功",
		"loaded_certificates": len(certificateMap),
	})
}

var login, loginError, notFound, panle, prism_tomorrow, prism_line_numbers_css, prism_core, prism_autoloader, prism_line_numbers_js, prism_copy_to_clipboard []byte

// 修改 readGinHtml 函数
func readGinHtml() {
	var err error
	login, err = staticFiles.ReadFile("static/login.html")
	if err != nil {
		stdlog.Printf("读取 login.html 失败: %v", err)
	}
	loginError, err = staticFiles.ReadFile("static/loginError.html")
	if err != nil {
		stdlog.Printf("读取 loginError.html 失败: %v", err)
	}
	notFound, err = staticFiles.ReadFile("static/404.html")
	if err != nil {
		stdlog.Printf("读取 404.html 失败: %v", err)
	}
	panle, err = staticFiles.ReadFile("static/panle.html")
	if err != nil {
		stdlog.Printf("读取 panle.html 失败: %v", err)
	}

	prism_tomorrow, err = prismFiles.ReadFile("static/out/prism-tomorrow.min.css")
	if err != nil {
		stdlog.Printf("读取 prism-tomorrow.min.css 失败: %v", err)
	}
	prism_line_numbers_css, err = prismFiles.ReadFile("static/out/prism-line-numbers.min.css")
	if err != nil {
		stdlog.Printf("读取 prism-line-numbers.min.css 失败: %v", err)
	}
	prism_core, err = prismFiles.ReadFile("static/out/prism-core.min.js")
	if err != nil {
		stdlog.Printf("读取 prism-core.min.js 失败: %v", err)
	}
	prism_autoloader, err = prismFiles.ReadFile("static/out/prism-autoloader.min.js")
	if err != nil {
		stdlog.Printf("读取 prism-autoloader.min.js 失败: %v", err)
	}
	prism_line_numbers_js, err = prismFiles.ReadFile("static/out/prism-line-numbers.min.js")
	if err != nil {
		stdlog.Printf("读取 prism-line-numbers.min.js 失败: %v", err)
	}
	prism_copy_to_clipboard, err = prismFiles.ReadFile("static/out/prism-copy-to-clipboard.min.js")
	if err != nil {
		stdlog.Printf("读取 prism-copy-to-clipboard.min.js 失败: %v", err)
	}
}

// 在需要认证的路由中使用中间件
func StartGinAPI() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	// 从 embed.FS 提供静态文件
	r.GET("/prism-tomorrow.min.css", func(ctx *gin.Context) {
		ctx.Header("Content-Type", "text/css; charset=utf-8")
		ctx.String(http.StatusOK, string(prism_tomorrow))
	})

	r.GET("/prism-line-numbers.min.css", func(ctx *gin.Context) {
		ctx.Header("Content-Type", "text/css; charset=utf-8")
		ctx.String(http.StatusOK, string(prism_line_numbers_css))
	})

	r.GET("/prism-autoloader.min.js", func(ctx *gin.Context) {
		ctx.Header("Content-Type", "application/javascript; charset=utf-8")
		ctx.String(http.StatusOK, string(prism_autoloader))
	})

	r.GET("/prism-core.min.js", func(ctx *gin.Context) {
		ctx.Header("Content-Type", "application/javascript; charset=utf-8")
		ctx.String(http.StatusOK, string(prism_core))
	})

	r.GET("/prism-line-numbers.min.js", func(ctx *gin.Context) {
		ctx.Header("Content-Type", "application/javascript; charset=utf-8")
		ctx.String(http.StatusOK, string(prism_line_numbers_js))
	})

	r.GET("/prism-copy-to-clipboard.min.js", func(ctx *gin.Context) {
		ctx.Header("Content-Type", "application/javascript; charset=utf-8")
		ctx.String(http.StatusOK, string(prism_copy_to_clipboard))
	})

	// 公开路由（不需要认证）
	r.POST("/login", loginHandler)
	r.GET(cfg.Secure, func(ctx *gin.Context) {
		ctx.Header("Content-Type", "text/html; charset=utf-8")
		ctx.String(http.StatusOK, string(login))
	})

	// 需要认证的路由组
	authGroup := r.Group("/")
	authGroup.Use(authMiddleware())
	{

		// 自定义规则管理路由
		authGroup.POST("/api/custom-rules", addCustomRuleHandler)
		authGroup.GET("/api/custom-rules", getCustomRulesHandler)
		authGroup.PUT("/api/custom-rules/:id", updateCustomRuleHandler)
		authGroup.DELETE("/api/custom-rules/:id", deleteCustomRuleHandler)
		authGroup.POST("/api/custom-rules/:id/toggle", toggleCustomRuleHandler)
		authGroup.GET("/api/custom-rules/export", exportCustomRulesHandler)
		authGroup.POST("/api/custom-rules/import", importCustomRulesHandler)
		authGroup.POST("/api/custom-rules/reload", reloadCustomRulesHandler)
		//---------ACL------------
		authGroup.POST("/api/acl/rules", addACLRuleHandler)
		authGroup.GET("/api/acl/rules", getACLRulesHandler)
		authGroup.DELETE("/api/acl/rules/:id", deleteACLRuleHandler)
		authGroup.POST("/api/acl/rules/:id/toggle", toggleACLRuleHandler)

		//-------------------缓存加速----------------------
		authGroup.GET("/api/cache/stats", getCacheStatsHandler)
		authGroup.POST("/api/cache/config", updateCacheConfigHandler)
		authGroup.POST("/api/cache/clear", clearCacheHandler)
		authGroup.GET("/api/cache/stats/detail", getCacheStatsDetailHandler) // 新增详细统计
		authGroup.GET("/api/cache/files", getCacheFilesHandler)
		authGroup.POST("/api/cache/files", getCacheFileContentHandler)
		authGroup.DELETE("/api/cache/files/delete", deleteCacheFileHandler) // 新增：删除单个缓存文件

		// 添加站点
		authGroup.POST("/api/site/add", addSiteHandler)
		authGroup.GET("/api/sites", getSitesHandler)
		authGroup.PUT("/api/site/update", updateSiteHandler) // 新增：更新站点信息
		authGroup.POST("/api/site/delete", deleteSiteHandler)
		authGroup.POST("/api/site/status", updateSiteStatusHandler) // 新增：更新站点状态
		authGroup.POST("/api/site/https", updateSiteHTTPSHandler)   // 新增：更新HTTPS状态

		// 证书管理
		authGroup.POST("/api/cert/upload", uploadCertHandler)
		authGroup.POST("/api/site/update-cert", updateSiteCertHandler)
		authGroup.POST("/api/cert/reload", reloadAllCertificatesHandler)

		//// ------------------- waf信息统计 -------------------
		authGroup.GET("/api/stats", getStatsHandler)

		//// -------------------心跳------------------------------
		authGroup.GET("/api/health", getSiteHealthHandler)
		authGroup.GET("/api/health/:id", checkSingleSiteHealthHandler)

		// 攻击日志管理
		authGroup.GET("/api/attack/logs", getAttackLogsHandler)          // 获取攻击日志
		authGroup.GET("/api/attack/stats", getAttackStatsHandler)        // 获取攻击统计
		authGroup.DELETE("/api/attack/logs", deleteAttackLogsHandler)    // 删除攻击日志
		authGroup.GET("/api/attack/export", exportAttackLogsHandler)     // 导出攻击日志
		authGroup.GET("/api/attack/logs/:id", getAttackLogDetailHandler) // 获取单个日志详情

		// 站点证书管理
		authGroup.POST("/api/site/add-with-cert", addSiteWithCertHandler)                  // 添加站点带证书
		authGroup.GET("/api/site/:id/certificate", getSiteCertificateHandler)              // 获取站点证书信息
		authGroup.POST("/api/site/:id/renew-certificate", renewSiteCertificateHandler)     // 重新生成证书
		authGroup.POST("/api/site/:id/replace-certificate", replaceSiteCertificateHandler) // 替换证书
		authGroup.POST("/api/site/:id/remove-certificate", removeSiteCertificateHandler)   // 移除证

		// CC防护管理
		authGroup.POST("/api/cc/rules", addCCRuleHandler)
		authGroup.GET("/api/cc/rules", getCCRulesHandler)
		authGroup.PUT("/api/cc/rules/:id", updateCCRuleHandler)
		authGroup.DELETE("/api/cc/rules/:id", deleteCCRuleHandler)
		authGroup.GET("/api/cc/stats", getCCStatsHandler)
		authGroup.GET("/api/cc/logs", getCCAttackLogsHandler)
		authGroup.POST("/api/cc/clear-counters", clearCCCountersHandler)

		// 在 authGroup 中添加设置相关的路由
		authGroup.GET("/api/settings", getSettingsHandler)
		authGroup.POST("/api/settings", updateSettingsHandler)

		//规则相关接口
		authGroup.POST("/api/rules/status", updateRuleStatusHandler)
		authGroup.GET("/api/rules/reload", reloadRulesHandler)
		authGroup.GET("/api/rule/blockRuleId", getBlockedRuleId)

		// 在 authGroup 中添加系统监控路由
		authGroup.GET("/api/monitor/system", getSystemMonitorHandler)
		authGroup.GET("/api/monitor/connections", getConnectionsHandler)
		authGroup.GET("/api/monitor/history", getMonitorHistoryHandler)

		// 流量统计路由
		authGroup.GET("/api/traffic/stats", getTrafficStatsHandler)
		authGroup.GET("/api/traffic/logs", getTrafficLogsHandler)
		authGroup.DELETE("/api/traffic/logs", deleteTrafficLogsHandler)
		authGroup.GET("/api/traffic/export", exportTrafficLogsHandler)
	}

	// 统一返回404页面
	r.NoRoute(func(ctx *gin.Context) {
		ctx.Header("Content-Type", "text/html; charset=utf-8")
		ctx.String(http.StatusNotFound, string(notFound))
	})

	stdlog.Println("Gin API 启动在 :8080")
	if err := r.Run(":8080"); err != nil {
		stdlog.Fatalf("Gin 启动失败: %v", err)
	}
}

var wafDir = "./static/waf"

func loadWAFPage(filename string) string {
	path := filepath.Join(wafDir, filename)
	content, err := ioutil.ReadFile(path)
	if err != nil {
		stdlog.Fatalf("加载文件 %s 失败: %v", filename, err)
	}
	return string(content)
}

// 初始化函数，程序启动时加载 HTML 文件
var interceptPage string
var NotFoundPage string
var proxyErrorPage string
var aclBlock string
var ccBlockPage string

func readWafHtml() {
	var err error
	interceptPageBytes, err := wafFiles.ReadFile("static/waf/intercept.html")
	if err != nil {
		stdlog.Printf("读取 intercept.html 失败: %v", err)
		interceptPage = "<html><body><h1>拦截页面</h1></body></html>"
	} else {
		interceptPage = string(interceptPageBytes)
	}

	notFoundBytes, err := wafFiles.ReadFile("static/waf/notfound.html")
	if err != nil {
		stdlog.Printf("读取 notfound.html 失败: %v", err)
		NotFoundPage = "<html><body><h1>页面未找到</h1></body></html>"
	} else {
		NotFoundPage = string(notFoundBytes)
	}

	proxyErrorBytes, err := wafFiles.ReadFile("static/waf/proxy_error.html")
	if err != nil {
		stdlog.Printf("读取 proxy_error.html 失败: %v", err)
		proxyErrorPage = "<html><body><h1>代理错误</h1></body></html>"
	} else {
		proxyErrorPage = string(proxyErrorBytes)
	}

	aclBlockBytes, err := wafFiles.ReadFile("static/waf/aclBlock.html")
	if err != nil {
		stdlog.Printf("读取 aclBlock.html 失败: %v", err)
		aclBlock = "<html><body><h1>ACL拦截</h1></body></html>"
	} else {
		aclBlock = string(aclBlockBytes)
	}

	ccBlockBytes, err := wafFiles.ReadFile("static/waf/ccBlock.html")
	if err != nil {
		stdlog.Printf("读取 ccBlock.html 失败: %v", err)
		ccBlockPage = "<html><body><h1>CC攻击拦截</h1></body></html>"
	} else {
		ccBlockPage = string(ccBlockBytes)
	}
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

// ------------------- WebSocket 代理结构 -------------------
type websocketProxy struct {
	backendURL *url.URL
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // 允许所有来源，生产环境应该更严格
	},
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

// ------------------- WebSocket 处理函数 -------------------
func (p *websocketProxy) serveWS(w http.ResponseWriter, req *http.Request) {
	// 查找目标站点
	host := req.Host
	var targetURL string
	var siteHost string

	// 只检查站点是否存在，不经过 WAF、ACL、CC
	for i := range sites {
		if strings.EqualFold(sites[i].Domain, host) && sites[i].Status == 1 {
			// 负载均衡选择上游服务器
			if sites[i].LoadBalanceAlgorithm != "" && len(sites[i].UpstreamServers) > 0 {
				selectedServer := selectUpstreamServer(&sites[i])
				if selectedServer != nil {
					targetURL = selectedServer.URL
				} else {
					targetURL = sites[i].TargetURL
				}
			} else {
				targetURL = sites[i].TargetURL
			}
			siteHost = strings.Split(targetURL, "://")[1]
			break
		}
	}

	if targetURL == "" {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(NotFoundPage))
		return
	}

	// 构建后端 WebSocket URL
	backendURL := *p.backendURL
	if strings.HasPrefix(targetURL, "https://") {
		backendURL.Scheme = "wss"
	} else {
		backendURL.Scheme = "ws"
	}
	backendURL.Path = req.URL.Path
	backendURL.RawQuery = req.URL.RawQuery

	// 开始 WebSocket 代理
	p.proxyWebSocket(w, req, &backendURL, siteHost)
}

func (p *websocketProxy) proxyWebSocket(w http.ResponseWriter, req *http.Request, backendURL *url.URL, siteHost string) {
	// 设置后端连接
	dialer := websocket.DefaultDialer

	// 创建新的请求头，完全手动控制
	header := http.Header{}

	// 只拷贝必要的头，排除所有 WebSocket 相关头
	for k, v := range req.Header {
		switch strings.ToLower(k) {
		case "upgrade", "connection", "sec-websocket-key", "sec-websocket-version",
			"sec-websocket-extensions", "sec-websocket-protocol", "sec-websocket-accept":
			// 跳过所有 WebSocket 特定头
			continue
		case "host":
			// 使用目标站点的 host
			header.Set("Host", siteHost)
		case "cookie", "user-agent", "accept", "accept-language", "accept-encoding":
			// 拷贝这些常用头
			header[k] = v
		default:
			// 对于其他头，只拷贝非 WebSocket 相关的
			if !strings.HasPrefix(strings.ToLower(k), "sec-websocket") {
				header[k] = v
			}
		}
	}

	// 设置必要的转发头
	header.Set("X-Forwarded-For", getClientIP(req))
	header.Set("X-Forwarded-Host", req.Host)
	header.Set("X-Forwarded-Proto", "http")
	if req.TLS != nil {
		header.Set("X-Forwarded-Proto", "https")
	}

	// 连接后端 WebSocket
	connBackend, resp, err := dialer.Dial(backendURL.String(), header)
	if err != nil {
		stdlog.Printf("WebSocket 后端连接失败: %v", err)
		stdlog.Printf("请求头: %v", header)
		if resp != nil {
			for k, v := range resp.Header {
				w.Header()[k] = v
			}
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
			resp.Body.Close()
		} else {
			http.Error(w, "WebSocket 代理错误", http.StatusBadGateway)
		}
		return
	}
	defer connBackend.Close()

	// 升级客户端连接
	connClient, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		stdlog.Printf("WebSocket 客户端升级失败: %v", err)
		return
	}
	defer connClient.Close()

	stdlog.Printf("WebSocket 代理建立: %s%s", req.Host, req.URL.Path)

	// 启动双向数据转发
	var wg sync.WaitGroup
	wg.Add(2)

	// 客户端 -> 后端
	go func() {
		defer wg.Done()
		defer connClient.Close()
		defer connBackend.Close()

		for {
			msgType, msg, err := connClient.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					stdlog.Printf("WebSocket 客户端读取错误: %v", err)
				}
				break
			}

			err = connBackend.WriteMessage(msgType, msg)
			if err != nil {
				stdlog.Printf("WebSocket 后端写入错误: %v", err)
				break
			}
		}
	}()

	// 后端 -> 客户端
	go func() {
		defer wg.Done()
		defer connClient.Close()
		defer connBackend.Close()

		for {
			msgType, msg, err := connBackend.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					stdlog.Printf("WebSocket 后端读取错误: %v", err)
				}
				break
			}

			err = connClient.WriteMessage(msgType, msg)
			if err != nil {
				stdlog.Printf("WebSocket 客户端写入错误: %v", err)
				break
			}
		}
	}()

	wg.Wait()
	stdlog.Printf("WebSocket 连接关闭: %s%s", req.Host, req.URL.Path)
}

// ------------------- 调试函数 -------------------

// ------------------- 攻击检测 -------------------
// ------------------- 攻击检测 -------------------
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

	// 拆分URL：路径部分和参数部分
	uri := req.URL.Path        // URI路径部分
	rawURL := req.URL.String() // 完整URL（用于向后兼容）

	// 提取URL参数：键和值
	var parameterKeys []string   // 参数键名列表
	var parameterValues []string // 参数值列表
	queryParams := req.URL.Query()
	for key, values := range queryParams {
		parameterKeys = append(parameterKeys, key)
		parameterValues = append(parameterValues, values...)
	}

	head := sb.String()

	// 对URI、参数键、参数值进行解码
	if isActivateUrlDecode {
		uri = MultiDecode(uri)
		rawURL = MultiDecode(rawURL)
		for i := range parameterKeys {
			parameterKeys[i] = MultiDecode(parameterKeys[i])
		}
		for i := range parameterValues {
			parameterValues[i] = MultiDecode(parameterValues[i])
		}
		head = MultiDecode(head)
		body = MultiDecode(body)
	}

	if isActivateBase64 {
		uri = tryBase64Decode(uri)
		rawURL = tryBase64Decode(rawURL)
		for i := range parameterKeys {
			parameterKeys[i] = tryBase64Decode(parameterKeys[i])
		}
		for i := range parameterValues {
			parameterValues[i] = tryBase64Decode(parameterValues[i])
		}
		head = tryBase64Decode(head)
		body = tryBase64Decode(body)
	}

	// 修复：如果规则匹配率为0，直接返回不拦截
	if RuleMatchRate == 0 {
		return false, nil
	}

	var rules []Rule
	if methodRules, ok := RULES[req.Method]; ok {
		// 只添加启用的规则
		for _, rule := range methodRules {
			if rule.Enabled {
				rules = append(rules, rule)
			}
		}
	}
	if anyRules, ok := RULES["any"]; ok {
		// 只添加启用的规则
		for _, rule := range anyRules {
			if rule.Enabled {
				rules = append(rules, rule)
			}
		}
	}

	// 修复：只有当 RuleMatchRate > 0 时才应用规则限制
	if RuleMatchRate > 0 && RuleMatchRate < 100 && len(rules) > 0 {
		limit := len(rules) * RuleMatchRate / 100
		if limit < 1 {
			limit = 1
		}
		rules = rules[:limit]
	}

	for _, rule := range rules {
		// 获取匹配结果，传入拆分后的URL组件
		matched, matchedValues := evaluateRule(rule, uri, rawURL, parameterKeys, parameterValues, head, body, isBodyNull)

		if matched {
			clientIP := getClientIP(req)
			log := AttackLog{
				Method:       req.Method,
				URL:          rawURL,
				Headers:      head,
				Body:         body,
				RuleName:     rule.Name,
				RuleID:       rule.ID,
				MatchedValue: strings.Join(matchedValues, "; "),
				ClientIP:     clientIP,
			}
			return true, &log
		}
	}

	return false, nil
}

// 评估单条规则
// 评估单条规则：uri为路径部分，rawURL为完整URL（向后兼容），parameterKeys和parameterValues为参数键值对
func evaluateRule(rule Rule, uri, rawURL string, parameterKeys, parameterValues []string, head, body string, isBodyNull bool) (bool, []string) {
	if len(rule.Judges) == 0 {
		return false, nil
	}

	var matchedValues []string
	var matchResults []bool

	// 评估每个judge
	for _, judge := range rule.Judges {
		var target string
		var matchedStr string

		switch judge.Position {
		case "uri":
			// URI路径部分（不包含参数）
			target = uri
			matchedStr = match(target, judge)

		case "parameter_key":
			// URL参数的键名
			// 遍历每个参数键名进行匹配
			for _, key := range parameterKeys {
				result := match(key, judge)
				if result != "" {
					matchedStr = result
					break
				}
			}

		case "parameter_value":
			// URL参数的值
			// 遍历每个参数值进行匹配
			for _, value := range parameterValues {
				result := match(value, judge)
				if result != "" {
					matchedStr = result
					break
				}
			}

		case "request_header":
			target = head
			matchedStr = match(target, judge)

		case "request_body":
			if isBodyNull {
				matchResults = append(matchResults, false)
				continue
			}
			target = body
			matchedStr = match(target, judge)

		default:
			// 向后兼容：如果position不是已知类型，使用完整URL（保持原有行为）
			target = rawURL
			matchedStr = match(target, judge)
		}

		// 根据 action 判断匹配结果
		judgeAction := judge.Action
		if judgeAction == "" {
			judgeAction = "is" // 默认值为 "is"
		}

		var judgeResult bool
		if judgeAction == "is" {
			// "is" 关系：匹配到内容即为真
			judgeResult = (matchedStr != "")
		} else if judgeAction == "not" {
			// "not" 关系：没有匹配到内容即为真
			judgeResult = (matchedStr == "")
		} else {
			// 未知的 action，默认使用 "is"
			judgeResult = (matchedStr != "")
		}

		matchResults = append(matchResults, judgeResult)
		if matchedStr != "" {
			matchedValues = append(matchedValues, matchedStr)
		}
	}

	// 根据relation判断最终结果
	var finalResult bool
	switch strings.ToLower(rule.Relation) {
	case "or":
		// OR关系：任意一个匹配即为真
		finalResult = false
		for _, result := range matchResults {
			if result {
				finalResult = true
				break
			}
		}
	case "and":
		// AND关系：全部匹配才为真
		finalResult = true
		for _, result := range matchResults {
			if !result {
				finalResult = false
				break
			}
		}
	default:
		// 默认使用AND关系（向后兼容）
		finalResult = true
		for _, result := range matchResults {
			if !result {
				finalResult = false
				break
			}
		}
	}

	return finalResult, matchedValues
}

// ------------------- Worker -------------------
func attackWorker() {
	for log := range attackChan {
		// 使用 Base64 编码存储，防止 MySQL 非 UTF-8 报错
		urlB64 := base64.StdEncoding.EncodeToString([]byte(log.URL))
		bodyB64 := base64.StdEncoding.EncodeToString([]byte(log.Body))
		headersB64 := base64.StdEncoding.EncodeToString([]byte(log.Headers))

		query := `
            INSERT INTO attacks (method, url, headers, body, rule_name, rule_id, matched_value, client_ip)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `
		_, err := db.Exec(query,
			log.Method, urlB64, headersB64, bodyB64,
			log.RuleName, log.RuleID, log.MatchedValue, log.ClientIP) // 添加client_ip
		if err != nil {
			fmt.Printf("写入攻击数据库失败: %v\n", err)
		}
	}
}

// ------------------- 规则加载 -------------------
func readRule() {
	RULES = make(map[string][]Rule)
	ruleDir := "./rule"

	filepath.WalkDir(ruleDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		if filepath.Ext(path) != ".yaml" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Printf("读取文件失败: %s, 错误: %v\n", path, err)
			return nil
		}

		if strings.HasPrefix(string(data), "[") {
			var rules []Rule
			if err := yaml.Unmarshal(data, &rules); err != nil {
				fmt.Printf("解析 JSON 数组失败: %s, 错误: %v\n", path, err)
				return nil
			}
			for i := range rules {
				r := &rules[i]
				// 如果 Judges 为空，尝试从 judges 字段读取（兼容性处理）
				if len(r.Judges) == 0 {
					var tempArray []map[string]interface{}
					if err := yaml.Unmarshal(data, &tempArray); err == nil && i < len(tempArray) {
						if judgesData, ok := tempArray[i]["judges"]; ok {
							// 将 judges 数据转换为 JSON 再解析
							judgesBytes, _ := json.Marshal(judgesData)
							if err := yaml.Unmarshal(judgesBytes, &r.Judges); err == nil {
								fmt.Printf("从 judges 字段加载规则数组中的第 %d 条: %s\n", i+1, path)
							}
						}
					}
				}
				// 设置默认启用状态
				if !r.Enabled {
					r.Enabled = true // 默认启用所有规则
				}
				for j := range r.Judges {
					if r.Judges[j].Rix != "" {
						r.Judges[j].regex, _ = regexp.Compile(r.Judges[j].Rix)
					}
				}
				RULES[r.Method] = append(RULES[r.Method], *r)
			}
		} else {
			var r Rule
			if err := yaml.Unmarshal(data, &r); err != nil {
				fmt.Printf("解析 JSON 失败: %s, 错误: %v\n", path, err)
				return nil
			}

			// 如果 Judges 为空，尝试从 judges 字段读取（兼容性处理）
			if len(r.Judges) == 0 {
				var tempMap map[string]interface{}
				if err := yaml.Unmarshal(data, &tempMap); err == nil {
					if judgesData, ok := tempMap["judges"]; ok {
						// 将 judges 数据转换为 JSON 再解析
						judgesBytes, _ := json.Marshal(judgesData)
						if err := yaml.Unmarshal(judgesBytes, &r.Judges); err == nil {
							fmt.Printf("从 judges 字段加载规则: %s\n", path)
						}
					}
				}
			}

			// 设置默认启用状态
			if !r.Enabled {
				r.Enabled = true // 默认启用所有规则
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
	enabledCount := 0
	for _, rules := range RULES {
		total += len(rules)
		for _, rule := range rules {
			if rule.Enabled {
				enabledCount++
			}
		}
	}

	fmt.Printf("所有规则加载完成！方法数: %d，总规则数: %d，启用规则数: %d\n", len(RULES), total, enabledCount)
}

// ------------------- 数据库 -------------------
func initDb() {
	// if !cfg.IsWriteDbAuto {
	// 	fmt.Println("isWriteDbAuto=false，跳过数据库初始化")
	// 	return
	// }

	// SQLite3 数据库文件路径
	dbPath := "./waf.db"
	var err error

	// 构建连接字符串，支持加密
	var connectionString string
	if cfg.Database.EncryptionKey != "" {
		// 使用加密连接
		connectionString = fmt.Sprintf("%s?_pragma_key=%s&_pragma_cipher_page_size=4096", dbPath, cfg.Database.EncryptionKey)
		fmt.Println("使用加密数据库连接")
	} else {
		// 使用非加密连接
		connectionString = dbPath
		fmt.Println("使用非加密数据库连接")
	}

	db, err = sql.Open("sqlite3", connectionString)
	if err != nil {
		panic(fmt.Errorf("连接 SQLite3 失败: %v", err))
	}

	// 优化连接池配置
	db.SetMaxOpenConns(50)                  // 减少最大连接数
	db.SetMaxIdleConns(10)                  // 减少空闲连接数
	db.SetConnMaxLifetime(time.Hour)        // 连接最大生命周期
	db.SetConnMaxIdleTime(10 * time.Minute) // 空闲连接超时

	if err := db.Ping(); err != nil {
		panic(fmt.Errorf("ping数据库失败: %w", err))
	}

	_, _ = db.Exec("DROP TABLE IF EXISTS attacks;")
	_, _ = db.Exec("DROP TABLE IF EXISTS sites;")
	_, _ = db.Exec("DROP TABLE IF EXISTS certificates;")

	createTable := `
    CREATE TABLE attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        method TEXT,
        url TEXT,
        headers TEXT,
        body TEXT,
        rule_name TEXT,
        rule_id TEXT,
        matched_value TEXT,
        client_ip TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );`
	if _, err := db.Exec(createTable); err != nil {
		panic(fmt.Errorf("建表失败: %v", err))
	}

	createCertTable := `
	CREATE TABLE IF NOT EXISTS certificates (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		cert_text TEXT NOT NULL,
		key_text TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err := db.Exec(createCertTable); err != nil {
		panic(fmt.Errorf("建表 certificates 失败: %v", err))
	}

	createTable1 := `
	CREATE TABLE IF NOT EXISTS sites (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		domain TEXT NOT NULL UNIQUE,
		target_url TEXT NOT NULL,
		enable_https INTEGER NOT NULL DEFAULT 0,
		cert_id INTEGER DEFAULT NULL,
		status INTEGER NOT NULL DEFAULT 1,
		load_balance_algorithm TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	if _, err := db.Exec(createTable1); err != nil {
		panic(fmt.Errorf("建表失败: %v", err))
	}

	// 添加负载均衡字段（如果不存在）
	_, _ = db.Exec("ALTER TABLE sites ADD COLUMN load_balance_algorithm TEXT DEFAULT '';")

	// 创建上游服务器表
	createUpstreamTable := `
	CREATE TABLE IF NOT EXISTS upstream_servers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		site_id INTEGER NOT NULL,
		url TEXT NOT NULL,
		weight INTEGER NOT NULL DEFAULT 1,
		status INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
	);`
	if _, err := db.Exec(createUpstreamTable); err != nil {
		panic(fmt.Errorf("建表upstream_servers失败: %v", err))
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

	_, err = db.Exec(insertSite, "宝塔", "baota.com", "http://127.0.0.1:32262", 1, certID, 1)
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
	rows, err := db.Query("SELECT id, name, domain, target_url, enable_https, cert_id, status, COALESCE(load_balance_algorithm, ''), created_at, updated_at FROM sites")
	if err != nil {
		panic(fmt.Errorf("查询失败: %v", err))
	}
	defer rows.Close()

	for rows.Next() {
		var s Site
		var lbAlgo string
		if err := rows.Scan(&s.ID, &s.Name, &s.Domain, &s.TargetURL, &s.EnableHTTPS, &s.CERTID, &s.Status, &lbAlgo, &s.CreatedAt, &s.UpdatedAt); err != nil {
			panic(fmt.Errorf("读取失败: %v", err))
		}
		s.LoadBalanceAlgorithm = lbAlgo

		// 加载该站点的上游服务器
		upstreamRows, err := db.Query("SELECT id, url, weight, status, created_at FROM upstream_servers WHERE site_id = ? AND status = 1", s.ID)
		if err == nil {
			defer upstreamRows.Close()
			var upstreams []UpstreamServer
			for upstreamRows.Next() {
				var us UpstreamServer
				if err := upstreamRows.Scan(&us.ID, &us.URL, &us.Weight, &us.Status, &us.CreatedAt); err == nil {
					us.SiteID = s.ID
					upstreams = append(upstreams, us)
				}
			}
			s.UpstreamServers = upstreams
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

	// 创建流量统计表
	createTrafficTable()

	// 现在 sites 变量里就是数据库的内容
	fmt.Printf("读取到 %d 条站点记录\n", len(sites))
	fmt.Printf("加载了 %d 个证书\n", len(certificateMap))

	initACL()

	fmt.Println("ACL 管理器已初始化")

	for i := 0; i < workerCount; i++ {
		go attackWorker()
	}

	fmt.Println("SQLite3 已连接，Worker 已启动，数据库已重置")
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
			stdlog.Printf("读取证书数据失败: %v", err)
			continue
		}

		// 从文本加载证书
		cert, err := tls.X509KeyPair([]byte(certText), []byte(keyText))
		if err != nil {
			stdlog.Printf("加载证书失败 %s: %v", domain, err)
			continue
		}

		certificateMap[domain] = cert
		certificateCount++
		stdlog.Printf("已加载证书: %s", domain)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("迭代证书记录失败: %v", err)
	}

	if certificateCount == 0 {
		stdlog.Println("警告: 没有从数据库加载任何证书")
	} else {
		stdlog.Printf("成功从数据库加载 %d 个证书", certificateCount)
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

	// 检查该域名是否启用了 HTTPS
	enableHTTPS := false
	for _, site := range sites {
		if strings.EqualFold(site.Domain, serverName) && site.Status == 1 {
			enableHTTPS = site.EnableHTTPS
			break
		}
	}

	// 如果该域名禁用了 HTTPS，返回错误
	if !enableHTTPS {
		return nil, fmt.Errorf("HTTPS is disabled for domain: %s", serverName)
	}

	if cert, ok := certificateMap[serverName]; ok {
		stdlog.Printf("使用证书: %s", serverName)
		return &cert, nil
	}

	// 如果没有找到精确匹配，尝试通配符匹配
	for domain, cert := range certificateMap {
		if matchesWildcard(serverName, domain) {
			stdlog.Printf("使用通配符证书: %s -> %s", serverName, domain)
			return &cert, nil
		}
	}

	// 返回默认证书（第一个证书）
	for _, cert := range certificateMap {
		stdlog.Printf("使用默认证书 for: %s", serverName)
		return &cert, nil
	}

	return nil, nil
}

func ReverseProxy() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)

	tlsConfig := &tls.Config{
		GetCertificate: getCertificate,

		MinVersion: tls.VersionTLS12, // 安全配置
	}

	// HTTP server
	httpSrv := &http.Server{
		Addr:    ":80",
		Handler: mux,
	}

	// HTTPS server
	httpsSrv := &http.Server{
		Addr:      ":443",
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	// 并行启动
	go func() {
		stdlog.Println("HTTP on :80")
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			stdlog.Fatalf("HTTP启动失败: %v", err)
		}
	}()

	stdlog.Println("HTTPS on :443")
	if err := httpsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		stdlog.Fatalf("HTTPS启动失败: %v", err)
	}
}

// ------------------- 添加站点带证书请求 -------------------
type AddSiteWithCertRequest struct {
	Name                 string              `json:"name" binding:"required"`
	Domain               string              `json:"domain" binding:"required"`
	TargetURL            string              `json:"target_url"` // 如果启用负载均衡则为可选
	EnableHTTPS          bool                `json:"enable_https"`
	ValidDays            int                 `json:"valid_days"`
	CertText             string              `json:"cert_text"`
	KeyText              string              `json:"key_text"`
	LoadBalanceAlgorithm string              `json:"load_balance_algorithm"` // "" 或 "round_robin" 或 "weighted"
	UpstreamServers      []UpstreamServerAdd `json:"upstream_servers"`
}

func generateSelfSignedCertWithDays(domain string, validDays int) (certPEM []byte, keyPEM []byte, err error) {
	// 生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("生成私钥失败: %v", err)
	}

	// 创建证书模板
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, nil, fmt.Errorf("生成序列号失败: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{"LittleFox WAF"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(validDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain, "*." + domain},
	}

	// 生成证书
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("生成证书失败: %v", err)
	}

	// 编码为 PEM 格式
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return certPEM, keyPEM, nil
}

// ------------------- 添加站点带证书接口 -------------------
// ------------------- 添加站点带证书接口 -------------------
// ------------------- 修改 addSiteWithCertHandler 函数 -------------------
func addSiteWithCertHandler(c *gin.Context) {
	var req map[string]interface{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 手动提取和转换字段
	addSiteReq := AddSiteWithCertRequest{
		Name:                 getString(req, "name"),
		Domain:               getString(req, "domain"),
		TargetURL:            getString(req, "target_url"),
		EnableHTTPS:          getBool(req, "enable_https"),
		CertText:             getString(req, "cert_text"),
		KeyText:              getString(req, "key_text"),
		LoadBalanceAlgorithm: getString(req, "load_balance_algorithm"),
	}

	// 处理上游服务器
	if upstreamServersData, exists := req["upstream_servers"]; exists {
		if upstreamList, ok := upstreamServersData.([]interface{}); ok {
			for _, us := range upstreamList {
				if usMap, ok := us.(map[string]interface{}); ok {
					addSiteReq.UpstreamServers = append(addSiteReq.UpstreamServers, UpstreamServerAdd{
						URL:    getString(usMap, "url"),
						Weight: getInt(usMap, "weight"),
					})
				}
			}
		}
	}

	// 处理 ValidDays 字段
	if validDays, exists := req["valid_days"]; exists {
		switch v := validDays.(type) {
		case string:
			if v != "" {
				if intVal, err := strconv.Atoi(v); err == nil {
					addSiteReq.ValidDays = intVal
				}
			}
		case float64: // JSON 数字默认是 float64
			addSiteReq.ValidDays = int(v)
		case int:
			addSiteReq.ValidDays = v
		}
	}

	// 验证必需字段
	if addSiteReq.Name == "" || addSiteReq.Domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name, domain 为必填字段"})
		return
	}

	// 如果未启用负载均衡，target_url是必需的
	if addSiteReq.LoadBalanceAlgorithm == "" && addSiteReq.TargetURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未启用负载均衡时，target_url 为必填字段"})
		return
	}

	// 如果启用了负载均衡，必须有上游服务器
	if addSiteReq.LoadBalanceAlgorithm != "" && len(addSiteReq.UpstreamServers) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "启用负载均衡时，必须至少配置一个上游服务器"})
		return
	}

	var certID interface{} = nil

	// 如果启用HTTPS，处理证书
	if addSiteReq.EnableHTTPS {
		var certPEM, keyPEM []byte
		var err error

		// 判断是上传证书还是自动生成
		if addSiteReq.CertText != "" && addSiteReq.KeyText != "" {
			// 使用上传的证书
			certPEM = []byte(addSiteReq.CertText)
			keyPEM = []byte(addSiteReq.KeyText)

			// 验证证书格式
			_, err = tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("证书格式无效: %v", err)})
				return
			}
		} else {
			// 自动生成证书
			validDays := addSiteReq.ValidDays
			if validDays == 0 {
				validDays = 365
			}
			certPEM, keyPEM, err = generateSelfSignedCertWithDays(addSiteReq.Domain, validDays)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("生成证书失败: %v", err)})
				return
			}
		}

		// 保存证书到数据库
		certName := fmt.Sprintf("%s - %s", addSiteReq.Name, addSiteReq.Domain)
		insertCert := `INSERT INTO certificates (name, cert_text, key_text) VALUES (?, ?, ?)`
		result, err := db.Exec(insertCert, certName, certPEM, keyPEM)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("保存证书失败: %v", err)})
			return
		}

		certID, _ = result.LastInsertId()

		// 热加载证书到内存
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			stdlog.Printf("加载证书失败: %v", err)
		} else {
			certificateMap[addSiteReq.Domain] = cert
			stdlog.Printf("新证书已加载: %s", addSiteReq.Domain)
		}
	}

	// 插入站点到数据库并获取ID
	// 如果没有target_url（使用负载均衡），使用第一个上游服务器作为默认值
	targetURL := addSiteReq.TargetURL
	if targetURL == "" && len(addSiteReq.UpstreamServers) > 0 {
		targetURL = addSiteReq.UpstreamServers[0].URL
	}

	insertSite := `INSERT INTO sites (name, domain, target_url, enable_https, cert_id, status, load_balance_algorithm) VALUES (?, ?, ?, ?, ?, ?, ?)`
	result, err := db.Exec(insertSite, addSiteReq.Name, addSiteReq.Domain, targetURL, boolToInt(addSiteReq.EnableHTTPS), certID, 1, addSiteReq.LoadBalanceAlgorithm)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("写入站点失败: %v", err)})
		return
	}

	// 获取插入的站点ID
	siteID, err := result.LastInsertId()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("获取站点ID失败: %v", err)})
		return
	}

	// 插入上游服务器
	var upstreamServers []UpstreamServer
	if addSiteReq.LoadBalanceAlgorithm != "" && len(addSiteReq.UpstreamServers) > 0 {
		insertUpstream := `INSERT INTO upstream_servers (site_id, url, weight, status) VALUES (?, ?, ?, ?)`
		for _, us := range addSiteReq.UpstreamServers {
			if us.URL != "" {
				if us.Weight <= 0 {
					us.Weight = 1 // 默认权重为1
				}
				_, err := db.Exec(insertUpstream, siteID, us.URL, us.Weight, 1)
				if err == nil {
					upstreamServers = append(upstreamServers, UpstreamServer{
						SiteID: int(siteID),
						URL:    us.URL,
						Weight: us.Weight,
						Status: 1,
					})
				}
			}
		}
	}

	// 热更新内存 sites 列表
	newSite := Site{
		ID:                   int(siteID), // 确保ID正确设置
		Name:                 addSiteReq.Name,
		Domain:               addSiteReq.Domain,
		TargetURL:            targetURL,
		EnableHTTPS:          addSiteReq.EnableHTTPS,
		Status:               1,
		LoadBalanceAlgorithm: addSiteReq.LoadBalanceAlgorithm,
		UpstreamServers:      upstreamServers,
	}
	if certID != nil {
		newSite.CERTID = sql.NullInt64{Int64: certID.(int64), Valid: true}
	}

	aclManager.mutex.Lock()
	sites = append(sites, newSite)
	aclManager.mutex.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"message": "站点添加成功",
		"site_id": siteID,
	})
}

// 辅助函数
func getString(m map[string]interface{}, key string) string {
	if val, exists := m[key]; exists {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getBool(m map[string]interface{}, key string) bool {
	if val, exists := m[key]; exists {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return false
}

func getInt(m map[string]interface{}, key string) int {
	if val, exists := m[key]; exists {
		switch v := val.(type) {
		case int:
			return v
		case float64:
			return int(v)
		case string:
			if intVal, err := strconv.Atoi(v); err == nil {
				return intVal
			}
		}
	}
	return 1 // 默认返回1
}

func getFloat64(m map[string]interface{}, key string) float64 {
	if val, exists := m[key]; exists {
		switch v := val.(type) {
		case float64:
			return v
		case int:
			return float64(v)
		case string:
			if floatVal, err := strconv.ParseFloat(v, 64); err == nil {
				return floatVal
			}
		}
	}
	return 0
}

// ------------------- 证书信息结构 -------------------
type CertificateDetail struct {
	Exists       bool   `json:"exists"`
	Domain       string `json:"domain"`
	ValidFrom    string `json:"valid_from"`
	ValidTo      string `json:"valid_to"`
	Issuer       string `json:"issuer"`
	IsSelfSigned bool   `json:"is_self_signed"`
}

// ------------------- 获取站点证书信息接口 -------------------
func getSiteCertificateHandler(c *gin.Context) {
	siteID := c.Param("id")

	var domain, certText string
	err := db.QueryRow(`
        SELECT s.domain, c.cert_text 
        FROM sites s 
        LEFT JOIN certificates c ON s.cert_id = c.id 
        WHERE s.id = ? AND s.enable_https = 1
    `, siteID).Scan(&domain, &certText)

	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"certificate": CertificateDetail{Exists: false},
		})
		return
	}

	// 解析证书信息
	block, _ := pem.Decode([]byte(certText))
	if block == nil {
		c.JSON(http.StatusOK, gin.H{
			"certificate": CertificateDetail{Exists: false},
		})
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"certificate": CertificateDetail{Exists: false},
		})
		return
	}

	certDetail := CertificateDetail{
		Exists:       true,
		Domain:       domain,
		ValidFrom:    cert.NotBefore.Format("2006-01-02 15:04:05"),
		ValidTo:      cert.NotAfter.Format("2006-01-02 15:04:05"),
		Issuer:       cert.Issuer.CommonName,
		IsSelfSigned: cert.Issuer.CommonName == cert.Subject.CommonName,
	}

	c.JSON(http.StatusOK, gin.H{
		"certificate": certDetail,
	})
}

// ------------------- 重新生成证书请求 -------------------
type RenewCertRequest struct {
	ValidDays int `json:"valid_days" binding:"min=1,max=3650"`
}

// ------------------- 重新生成证书接口 -------------------
func renewSiteCertificateHandler(c *gin.Context) {
	siteID := c.Param("id")

	var req RenewCertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 获取站点信息
	var domain string
	var currentCertID int64
	err := db.QueryRow("SELECT domain, cert_id FROM sites WHERE id = ? AND enable_https = 1", siteID).Scan(&domain, &currentCertID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "站点不存在或未启用HTTPS"})
		return
	}

	// 生成新证书
	certPEM, keyPEM, err := generateSelfSignedCertWithDays(domain, req.ValidDays)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("生成证书失败: %v", err)})
		return
	}

	// 更新证书
	_, err = db.Exec("UPDATE certificates SET cert_text = ?, key_text = ? WHERE id = ?", certPEM, keyPEM, currentCertID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("更新证书失败: %v", err)})
		return
	}

	// 热加载新证书
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		stdlog.Printf("加载新证书失败: %v", err)
	} else {
		certificateMap[domain] = cert
		stdlog.Printf("证书已更新: %s", domain)
	}

	c.JSON(http.StatusOK, gin.H{"message": "证书重新生成成功"})
}

// ------------------- 替换证书请求 -------------------
type ReplaceCertRequest struct {
	CertText string `json:"cert_text" binding:"required"`
	KeyText  string `json:"key_text" binding:"required"`
}

// ------------------- 替换证书接口 -------------------
func replaceSiteCertificateHandler(c *gin.Context) {
	siteID := c.Param("id")

	var req ReplaceCertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 验证证书格式
	_, err := tls.X509KeyPair([]byte(req.CertText), []byte(req.KeyText))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("证书格式无效: %v", err)})
		return
	}

	// 获取站点信息
	var domain string
	var currentCertID int64
	err = db.QueryRow("SELECT domain, cert_id FROM sites WHERE id = ? AND enable_https = 1", siteID).Scan(&domain, &currentCertID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "站点不存在或未启用HTTPS"})
		return
	}

	// 更新证书
	_, err = db.Exec("UPDATE certificates SET cert_text = ?, key_text = ? WHERE id = ?", req.CertText, req.KeyText, currentCertID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("更新证书失败: %v", err)})
		return
	}

	// 热加载新证书
	cert, err := tls.X509KeyPair([]byte(req.CertText), []byte(req.KeyText))
	if err != nil {
		stdlog.Printf("加载新证书失败: %v", err)
	} else {
		certificateMap[domain] = cert
		stdlog.Printf("证书已替换: %s", domain)
	}

	c.JSON(http.StatusOK, gin.H{"message": "证书替换成功"})
}

// ------------------- 移除证书接口 -------------------
func removeSiteCertificateHandler(c *gin.Context) {
	siteID := c.Param("id")

	// 获取站点域名
	var domain string
	err := db.QueryRow("SELECT domain FROM sites WHERE id = ?", siteID).Scan(&domain)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "站点不存在"})
		return
	}

	// 禁用HTTPS并清除证书ID
	_, err = db.Exec("UPDATE sites SET enable_https = 0, cert_id = NULL WHERE id = ?", siteID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("更新站点失败: %v", err)})
		return
	}

	// 从内存中移除证书
	delete(certificateMap, domain)

	// 热更新内存中的站点信息
	aclManager.mutex.Lock()
	for i, site := range sites {
		if string(site.ID) == siteID {
			sites[i].EnableHTTPS = false
			sites[i].CERTID = sql.NullInt64{Valid: false}
			break
		}
	}
	aclManager.mutex.Unlock()

	stdlog.Printf("站点HTTPS已禁用，证书已移除: %s", domain)

	c.JSON(http.StatusOK, gin.H{"message": "证书已移除，HTTPS已禁用"})
}

// ------------------- 系统设置结构 -------------------
// ------------------- 系统设置结构 -------------------
type SystemSettings struct {
	EnableAntiDevTools  bool `json:"enable_anti_devtools"`
	EnableJSObfuscation bool `json:"enable_js_obfuscation"` // 新增：JS混淆开关
	RuleMatchRate       int  `json:"rule_match_rate"`
	Base64Depth         int  `json:"base64_depth"`
	URLDepth            int  `json:"url_depth"`
}

func debugPrintRequestWithBody(req *http.Request, bodyBytes []byte) {
	fmt.Printf("\n=== 发送请求 ===\n")
	fmt.Printf("%s %s %s\n", req.Method, req.URL.RequestURI(), req.Proto)

	// 输出 Host
	fmt.Printf("Host: %s\n", req.Host)

	// 输出请求头
	for key, values := range req.Header {
		for _, value := range values {
			fmt.Printf("%s: %s\n", key, value)
		}
	}

	// 输出空行分隔头部和主体
	fmt.Println()

	// 输出请求体 - 使用传入的 bodyBytes
	if bodyBytes != nil && len(bodyBytes) > 0 {
		contentType := req.Header.Get("Content-Type")

		if strings.Contains(contentType, "application/x-www-form-urlencoded") {
			fmt.Printf("表单数据 (%d bytes):\n", len(bodyBytes))
			if values, err := url.ParseQuery(string(bodyBytes)); err == nil {
				for key, vals := range values {
					for _, val := range vals {
						fmt.Printf("  %s: %s\n", key, val)
					}
				}
			} else {
				fmt.Printf("解析表单数据失败: %v\n", err)
				fmt.Printf("原始数据: %s\n", string(bodyBytes))
			}
		} else if strings.Contains(contentType, "application/json") {
			fmt.Printf("JSON 数据 (%d bytes):\n", len(bodyBytes))
			var prettyJSON bytes.Buffer
			if err := json.Indent(&prettyJSON, bodyBytes, "", "  "); err == nil {
				fmt.Printf("%s\n", prettyJSON.String())
			} else {
				fmt.Printf("%s\n", string(bodyBytes))
			}
		} else if strings.Contains(contentType, "multipart/form-data") {
			fmt.Printf("Multipart 表单数据 (%d bytes):\n", len(bodyBytes))
			fmt.Printf("%s\n", string(bodyBytes))
		} else {
			fmt.Printf("原始数据 (%d bytes):\n", len(bodyBytes))
			// 限制输出长度，避免控制台被刷屏
			if len(bodyBytes) > 1024 {
				fmt.Printf("%s\n[... 数据过长，已截断 ...]\n", string(bodyBytes[:1024]))
			} else {
				fmt.Printf("%s\n", string(bodyBytes))
			}
		}
	} else {
		fmt.Println("[空请求体]")
	}

	fmt.Printf("=== 请求结束 ===\n\n")
}

// ------------------- 更新设置接口 -------------------
func updateSettingsHandler(c *gin.Context) {
	var settings SystemSettings
	if err := c.ShouldBindJSON(&settings); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 验证参数范围
	if settings.RuleMatchRate < 0 || settings.RuleMatchRate > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "规则匹配率必须在0-100之间"})
		return
	}
	if settings.Base64Depth < 0 || settings.Base64Depth > 10 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Base64解码深度必须在0-10之间"})
		return
	}
	if settings.URLDepth < 0 || settings.URLDepth > 10 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "URL解码深度必须在0-10之间"})
		return
	}

	// 更新全局变量
	EnableAntiDevTools = settings.EnableAntiDevTools
	EnableJSObfuscation = settings.EnableJSObfuscation // 新增：更新JS混淆设置
	RuleMatchRate = settings.RuleMatchRate
	maxDepth = settings.Base64Depth
	maxUrlDepth = settings.URLDepth

	c.JSON(http.StatusOK, gin.H{
		"message":  "系统设置更新成功",
		"settings": settings,
	})
}

// ------------------- 系统监控数据结构 -------------------
type SystemMonitorResponse struct {
	PortStats   PortStats   `json:"port_stats"`
	CPUStats    CPUStats    `json:"cpu_stats"`
	MemoryStats MemoryStats `json:"memory_stats"`
	Timestamp   string      `json:"timestamp"`
}

type PortStats struct {
	Port80Rate       string `json:"port_80_rate"`      // 80端口速率
	Port443Rate      string `json:"port_443_rate"`     // 443端口速率
	TotalConnections int    `json:"total_connections"` // 总连接数
}

type CPUStats struct {
	UsagePercent  string `json:"usage_percent"`   // CPU使用率
	LoadAverage1  string `json:"load_average_1"`  // 1分钟负载
	LoadAverage5  string `json:"load_average_5"`  // 5分钟负载
	LoadAverage15 string `json:"load_average_15"` // 15分钟负载
	Cores         int    `json:"cores"`           // CPU核心数
}

type MemoryStats struct {
	Total        string `json:"total"`         // 总内存
	Used         string `json:"used"`          // 已使用内存
	Available    string `json:"available"`     // 可用内存
	UsagePercent string `json:"usage_percent"` // 内存使用率
}

// ------------------- 网络连接统计 -------------------
type ConnectionInfo struct {
	Protocol  string `json:"protocol"`
	LocalPort string `json:"local_port"`
	State     string `json:"state"`
}

var (
	lastPort80Count  int
	lastPort443Count int
	lastCheckTime    time.Time
	portStatsMutex   sync.RWMutex
)

// ------------------- 初始化端口统计 -------------------
func initPortStats() {
	lastCheckTime = time.Now()
	lastPort80Count = getCurrentConnections(80)
	lastPort443Count = getCurrentConnections(443)

	// 启动端口统计更新协程
	go updatePortStatsWorker()
}

// ------------------- 更新端口统计工作器 -------------------
func updatePortStatsWorker() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		portStatsMutex.Lock()
		lastPort80Count = getCurrentConnections(80)
		lastPort443Count = getCurrentConnections(443)
		lastCheckTime = time.Now()
		portStatsMutex.Unlock()
	}
}

// ------------------- 获取当前端口连接数 -------------------
func getCurrentConnections(port int) int {
	// 方法1: 使用netstat命令
	cmd := exec.Command("netstat", "-an", "|", "grep", fmt.Sprintf(":%d", port), "|", "wc", "-l")
	output, err := cmd.Output()
	if err == nil {
		count, err := strconv.Atoi(strings.TrimSpace(string(output)))
		if err == nil {
			return count
		}
	}

	// 方法2: 读取/proc/net/tcp和tcp6
	tcpFiles := []string{"/proc/net/tcp", "/proc/net/tcp6"}
	total := 0

	for _, file := range tcpFiles {
		content, err := ioutil.ReadFile(file)
		if err != nil {
			continue
		}

		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			if strings.Contains(line, fmt.Sprintf(":%04X", port)) {
				total++
			}
		}
	}

	return total
}

// ------------------- 获取端口速率 -------------------
func getPortStats() PortStats {
	portStatsMutex.RLock()
	defer portStatsMutex.RUnlock()

	current80 := getCurrentConnections(80)
	current443 := getCurrentConnections(443)

	// 计算连接变化率（基于上次统计）
	timeDiff := time.Since(lastCheckTime).Seconds()
	if timeDiff < 1 {
		timeDiff = 1
	}

	rate80 := float64(current80-lastPort80Count) / timeDiff
	rate443 := float64(current443-lastPort443Count) / timeDiff

	return PortStats{
		Port80Rate:       fmt.Sprintf("%.2f conn/s", rate80),
		Port443Rate:      fmt.Sprintf("%.2f conn/s", rate443),
		TotalConnections: current80 + current443,
	}
}

// ------------------- 获取CPU统计信息 -------------------
func getCPUStats() CPUStats {
	// 获取CPU使用率
	usagePercent, err := getCPUUsage()
	if err != nil {
		stdlog.Printf("获取CPU使用率失败: %v", err)
		usagePercent = 0
	}

	// 获取负载平均值
	loadAvg, err := getLoadAverage()
	if err != nil {
		stdlog.Printf("获取负载平均值失败: %v", err)
		loadAvg = [3]float64{0, 0, 0}
	}

	// 获取CPU核心数
	cores, err := getCPUCores()
	if err != nil {
		stdlog.Printf("获取CPU核心数失败: %v", err)
		cores = 1
	}

	return CPUStats{
		UsagePercent:  fmt.Sprintf("%.2f%%", usagePercent),
		LoadAverage1:  fmt.Sprintf("%.2f", loadAvg[0]),
		LoadAverage5:  fmt.Sprintf("%.2f", loadAvg[1]),
		LoadAverage15: fmt.Sprintf("%.2f", loadAvg[2]),
		Cores:         cores,
	}
}

// ------------------- 获取CPU使用率 -------------------
func getCPUUsage() (float64, error) {
	// 读取/proc/stat获取CPU信息
	content, err := ioutil.ReadFile("/proc/stat")
	if err != nil {
		return 0, err
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) >= 8 {
				user, _ := strconv.ParseUint(fields[1], 10, 64)
				nice, _ := strconv.ParseUint(fields[2], 10, 64)
				system, _ := strconv.ParseUint(fields[3], 10, 64)
				idle, _ := strconv.ParseUint(fields[4], 10, 64)
				iowait, _ := strconv.ParseUint(fields[5], 10, 64)
				irq, _ := strconv.ParseUint(fields[6], 10, 64)
				softirq, _ := strconv.ParseUint(fields[7], 10, 64)

				total := user + nice + system + idle + iowait + irq + softirq
				used := total - idle

				if total > 0 {
					return float64(used) / float64(total) * 100, nil
				}
			}
		}
	}

	return 0, fmt.Errorf("无法解析CPU信息")
}

// ------------------- 获取负载平均值 -------------------
func getLoadAverage() ([3]float64, error) {
	content, err := ioutil.ReadFile("/proc/loadavg")
	if err != nil {
		return [3]float64{0, 0, 0}, err
	}

	fields := strings.Fields(string(content))
	if len(fields) >= 3 {
		var load [3]float64
		for i := 0; i < 3; i++ {
			load[i], _ = strconv.ParseFloat(fields[i], 64)
		}
		return load, nil
	}

	return [3]float64{0, 0, 0}, fmt.Errorf("无法解析负载平均值")
}

// ------------------- 获取CPU核心数 -------------------
func getCPUCores() (int, error) {
	content, err := ioutil.ReadFile("/proc/cpuinfo")
	if err != nil {
		return 0, err
	}

	cores := 0
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "processor") {
			cores++
		}
	}

	if cores == 0 {
		return 1, nil
	}

	return cores, nil
}

// ------------------- 获取内存统计信息 -------------------
func getMemoryStats() MemoryStats {
	content, err := ioutil.ReadFile("/proc/meminfo")
	if err != nil {
		stdlog.Printf("读取内存信息失败: %v", err)
		return MemoryStats{
			Total:        "N/A",
			Used:         "N/A",
			Available:    "N/A",
			UsagePercent: "N/A",
		}
	}

	var total, available, free, buffers, cached uint64

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		value, _ := strconv.ParseUint(fields[1], 10, 64)

		switch fields[0] {
		case "MemTotal:":
			total = value
		case "MemAvailable:":
			available = value
		case "MemFree:":
			free = value
		case "Buffers:":
			buffers = value
		case "Cached:":
			cached = value
		}
	}

	// 如果没有MemAvailable，则计算可用内存
	if available == 0 {
		available = free + buffers + cached
	}

	used := total - available
	usagePercent := 0.0
	if total > 0 {
		usagePercent = float64(used) / float64(total) * 100
	}

	return MemoryStats{
		Total:        formatBytes(total * 1024), // 转换为字节
		Used:         formatBytes(used * 1024),
		Available:    formatBytes(available * 1024),
		UsagePercent: fmt.Sprintf("%.2f%%", usagePercent),
	}
}

// ------------------- 格式化字节大小 -------------------
func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// ------------------- 获取系统监控信息接口 -------------------
func getSystemMonitorHandler(c *gin.Context) {
	// 并行获取各种统计信息
	var portStats PortStats
	var cpuStats CPUStats
	var memoryStats MemoryStats

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		portStats = getPortStats()
	}()

	go func() {
		defer wg.Done()
		cpuStats = getCPUStats()
	}()

	go func() {
		defer wg.Done()
		memoryStats = getMemoryStats()
	}()

	wg.Wait()

	response := SystemMonitorResponse{
		PortStats:   portStats,
		CPUStats:    cpuStats,
		MemoryStats: memoryStats,
		Timestamp:   time.Now().Format("2006-01-02 15:04:05"),
	}

	c.JSON(http.StatusOK, response)
}

// ------------------- 获取实时连接列表接口 -------------------
func getConnectionsHandler(c *gin.Context) {
	connections, err := getCurrentConnectionsList()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("获取连接列表失败: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"connections": connections,
		"count":       len(connections),
		"timestamp":   time.Now().Format("2006-01-02 15:04:05"),
	})
}

// ------------------- 流量统计 API -------------------
// 获取流量统计信息
func getTrafficStatsHandler(c *gin.Context) {
	var stats TrafficStats
	stats.StatusCodes = make(map[int]int64)
	// 初始化切片，避免返回null
	stats.TopDomains = make([]DomainStat, 0)
	stats.TopPaths = make([]PathStat, 0)
	stats.TopIPs = make([]IPStat, 0)
	stats.HourlyStats = make([]HourlyStat, 0)
	stats.MethodStats = make([]MethodStat, 0)
	stats.RecentTraffic = make([]TrafficLog, 0)

	// 总请求数
	err := db.QueryRow("SELECT COUNT(*) FROM traffic_logs").Scan(&stats.TotalRequests)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("查询总请求数失败: %v", err)})
		return
	}

	// 今日请求数
	today := time.Now().Format("2006-01-02")
	err = db.QueryRow("SELECT COUNT(*) FROM traffic_logs WHERE date(created_at) = ?", today).Scan(&stats.TodayRequests)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("查询今日请求数失败: %v", err)})
		return
	}

	// 总流量（字节）
	var totalBytes sql.NullInt64
	err = db.QueryRow("SELECT SUM(request_size + response_size) FROM traffic_logs").Scan(&totalBytes)
	if err == nil && totalBytes.Valid {
		stats.TotalBytes = totalBytes.Int64
	}

	// 今日流量
	var todayBytes sql.NullInt64
	err = db.QueryRow("SELECT SUM(request_size + response_size) FROM traffic_logs WHERE date(created_at) = ?", today).Scan(&todayBytes)
	if err == nil && todayBytes.Valid {
		stats.TodayBytes = todayBytes.Int64
	}

	// 平均响应时间
	var avgTime sql.NullFloat64
	err = db.QueryRow("SELECT AVG(response_time) FROM traffic_logs").Scan(&avgTime)
	if err == nil && avgTime.Valid {
		stats.AvgResponseTime = avgTime.Float64
	}

	// 缓存命中率计算
	// 问题：很多应该被缓存的请求被标记为BYPASS，导致命中率计算不准确
	// 解决方案：使用所有GET 200请求作为分母（因为这些请求理论上都应该考虑缓存）
	var cacheHits, totalCacheRequests sql.NullInt64
	// 计算缓存命中数（HIT）
	db.QueryRow("SELECT COUNT(*) FROM traffic_logs WHERE cache_status = 'HIT'").Scan(&cacheHits)
	// 使用所有GET请求且状态码为200的请求作为分母（包括HIT、MISS、BYPASS）
	// 因为这些请求理论上都应该考虑缓存
	db.QueryRow("SELECT COUNT(*) FROM traffic_logs WHERE method = 'GET' AND status_code = 200").Scan(&totalCacheRequests)

	if totalCacheRequests.Valid && totalCacheRequests.Int64 > 0 {
		stats.CacheHitRate = float64(cacheHits.Int64) / float64(totalCacheRequests.Int64) * 100
		stdlog.Printf("缓存命中率统计: HIT=%d, 可缓存请求(GET 200)=%d, 命中率=%.2f%%",
			cacheHits.Int64, totalCacheRequests.Int64, stats.CacheHitRate)
	} else {
		stats.CacheHitRate = 0
		stdlog.Printf("缓存命中率统计: 无数据，HIT=%d", cacheHits.Int64)
	}

	// 状态码统计
	rows, err := db.Query(`
        SELECT status_code, COUNT(*) as count 
        FROM traffic_logs 
        GROUP BY status_code 
        ORDER BY count DESC
    `)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var code int
			var count int64
			if err := rows.Scan(&code, &count); err == nil {
				stats.StatusCodes[code] = count
			}
		}
	}

	// 热门域名
	rows, err = db.Query(`
        SELECT domain, COUNT(*) as requests, SUM(request_size + response_size) as bytes, AVG(response_time) as avg_time
        FROM traffic_logs 
        GROUP BY domain 
        ORDER BY requests DESC 
        LIMIT 10
    `)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var domain DomainStat
			var bytes sql.NullInt64
			var avgTime sql.NullFloat64
			err := rows.Scan(&domain.Domain, &domain.Requests, &bytes, &avgTime)
			if err == nil {
				if bytes.Valid {
					domain.Bytes = bytes.Int64
				}
				if avgTime.Valid {
					domain.AvgTime = avgTime.Float64
				}
				stats.TopDomains = append(stats.TopDomains, domain)
			}
		}
	}

	// 热门路径
	rows, err = db.Query(`
        SELECT path, COUNT(*) as requests, SUM(request_size + response_size) as bytes, AVG(response_time) as avg_time
        FROM traffic_logs 
        GROUP BY path 
        ORDER BY requests DESC 
        LIMIT 10
    `)
	if err != nil {
		stdlog.Printf("查询热门路径失败: %v", err)
	} else {
		defer rows.Close()
		for rows.Next() {
			var path PathStat
			var bytes sql.NullInt64
			var avgTime sql.NullFloat64
			err := rows.Scan(&path.Path, &path.Requests, &bytes, &avgTime)
			if err != nil {
				stdlog.Printf("扫描路径数据失败: %v", err)
				continue
			}
			if bytes.Valid {
				path.Bytes = bytes.Int64
			} else {
				path.Bytes = 0
			}
			if avgTime.Valid {
				path.AvgTime = avgTime.Float64
			} else {
				path.AvgTime = 0
			}
			stats.TopPaths = append(stats.TopPaths, path)
		}
	}

	// 热门IP
	rows, err = db.Query(`
        SELECT client_ip, COUNT(*) as requests, COALESCE(SUM(request_size + response_size), 0) as bytes, MAX(created_at) as last_seen
        FROM traffic_logs 
        GROUP BY client_ip 
        ORDER BY requests DESC 
        LIMIT 10
    `)
	if err != nil {
		stdlog.Printf("查询热门IP失败: %v", err)
	} else {
		defer rows.Close()
		count := 0
		for rows.Next() {
			count++
			var ip IPStat
			var bytes int64
			var lastSeenStr sql.NullString
			err := rows.Scan(&ip.IP, &ip.Requests, &bytes, &lastSeenStr)
			if err != nil {
				stdlog.Printf("扫描IP数据失败: %v, 这是第%d行", err, count)
				continue
			}
			ip.Bytes = bytes
			if lastSeenStr.Valid {
				// 尝试解析时间字符串
				if t, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", lastSeenStr.String); err == nil {
					ip.LastSeen = t.Format("2006-01-02 15:04:05")
				} else if t, err := time.Parse("2006-01-02 15:04:05", lastSeenStr.String); err == nil {
					ip.LastSeen = t.Format("2006-01-02 15:04:05")
				} else {
					ip.LastSeen = lastSeenStr.String
				}
			} else {
				ip.LastSeen = ""
			}
			stdlog.Printf("成功扫描IP: %s, 请求数: %d, 流量: %d", ip.IP, ip.Requests, ip.Bytes)
			stats.TopIPs = append(stats.TopIPs, ip)
		}
		stdlog.Printf("查询到 %d 个热门IP（遍历了 %d 行）", len(stats.TopIPs), count)
		if len(stats.TopIPs) == 0 && count == 0 {
			stdlog.Printf("警告: 热门IP查询返回空结果，但数据库中有 %d 条流量记录", stats.TotalRequests)
		}
	}

	// 24小时统计
	rows, err = db.Query(`
        SELECT strftime('%Y-%m-%d %H:00:00', created_at) as hour, COUNT(*) as count 
        FROM traffic_logs 
        WHERE created_at >= datetime('now', '-24 hours')
        GROUP BY hour 
        ORDER BY hour
    `)
	if err != nil {
		stdlog.Printf("查询24小时统计失败: %v", err)
	} else {
		defer rows.Close()
		for rows.Next() {
			var hourly HourlyStat
			if err := rows.Scan(&hourly.Hour, &hourly.Count); err != nil {
				stdlog.Printf("扫描24小时数据失败: %v", err)
				continue
			}
			stdlog.Printf("24小时统计: %s, 数量: %d", hourly.Hour, hourly.Count)
			stats.HourlyStats = append(stats.HourlyStats, hourly)
		}
		stdlog.Printf("查询到 %d 个24小时统计点", len(stats.HourlyStats))
	}

	// HTTP方法统计
	rows, err = db.Query(`
        SELECT method, COUNT(*) as count 
        FROM traffic_logs 
        GROUP BY method 
        ORDER BY count DESC
    `)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var method MethodStat
			if err := rows.Scan(&method.Method, &method.Count); err == nil {
				stats.MethodStats = append(stats.MethodStats, method)
			}
		}
	}

	// 最近的流量记录
	rows, err = db.Query(`
        SELECT id, domain, path, method, status_code, client_ip, user_agent, referer, 
               request_size, response_size, response_time, cache_status, created_at
        FROM traffic_logs 
        ORDER BY created_at DESC 
        LIMIT 50
    `)
	if err != nil {
		stdlog.Printf("查询最近流量记录失败: %v", err)
	} else {
		defer rows.Close()
		for rows.Next() {
			var log TrafficLog
			err := rows.Scan(&log.ID, &log.Domain, &log.Path, &log.Method, &log.StatusCode,
				&log.ClientIP, &log.UserAgent, &log.Referer, &log.RequestSize, &log.ResponseSize,
				&log.ResponseTime, &log.CacheStatus, &log.CreatedAt)
			if err != nil {
				stdlog.Printf("扫描流量记录失败: %v", err)
				continue
			}
			stats.RecentTraffic = append(stats.RecentTraffic, log)
		}
	}

	c.JSON(http.StatusOK, stats)
}

// 获取流量日志列表
func getTrafficLogsHandler(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	domain := c.Query("domain")
	statusCode := c.Query("status_code")
	clientIP := c.Query("client_ip")
	startTime := c.Query("start_time")
	endTime := c.Query("end_time")

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 500 {
		pageSize = 50
	}

	offset := (page - 1) * pageSize

	// 构建查询条件
	where := "1=1"
	args := []interface{}{}

	if domain != "" {
		where += " AND domain = ?"
		args = append(args, domain)
	}
	if statusCode != "" {
		where += " AND status_code = ?"
		args = append(args, statusCode)
	}
	if clientIP != "" {
		where += " AND client_ip = ?"
		args = append(args, clientIP)
	}
	if startTime != "" {
		where += " AND created_at >= ?"
		args = append(args, startTime)
	}
	if endTime != "" {
		where += " AND created_at <= ?"
		args = append(args, endTime)
	}

	// 查询总数
	var total int
	countQuery := "SELECT COUNT(*) FROM traffic_logs WHERE " + where
	err := db.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("查询总数失败: %v", err)})
		return
	}

	// 查询数据
	query := `
        SELECT id, domain, path, method, status_code, client_ip, user_agent, referer, 
               request_size, response_size, response_time, cache_status, created_at
        FROM traffic_logs 
        WHERE ` + where + `
        ORDER BY created_at DESC 
        LIMIT ? OFFSET ?
    `
	args = append(args, pageSize, offset)

	rows, err := db.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("查询失败: %v", err)})
		return
	}
	defer rows.Close()

	var logs []TrafficLog
	for rows.Next() {
		var log TrafficLog
		err := rows.Scan(&log.ID, &log.Domain, &log.Path, &log.Method, &log.StatusCode,
			&log.ClientIP, &log.UserAgent, &log.Referer, &log.RequestSize, &log.ResponseSize,
			&log.ResponseTime, &log.CacheStatus, &log.CreatedAt)
		if err == nil {
			logs = append(logs, log)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":      logs,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
		"pages":     (total + pageSize - 1) / pageSize,
	})
}

// 删除流量日志
func deleteTrafficLogsHandler(c *gin.Context) {
	var req struct {
		IDs    []int64 `json:"ids"`
		Before string  `json:"before"`
		All    bool    `json:"all"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var result sql.Result
	var err error

	if req.All {
		result, err = db.Exec("DELETE FROM traffic_logs")
	} else if len(req.IDs) > 0 {
		query := "DELETE FROM traffic_logs WHERE id IN (" + strings.Repeat("?,", len(req.IDs)-1) + "?)"
		args := make([]interface{}, len(req.IDs))
		for i, id := range req.IDs {
			args[i] = id
		}
		result, err = db.Exec(query, args...)
	} else if req.Before != "" {
		result, err = db.Exec("DELETE FROM traffic_logs WHERE created_at < ?", req.Before)
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请提供删除条件"})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("删除失败: %v", err)})
		return
	}

	affected, _ := result.RowsAffected()
	c.JSON(http.StatusOK, gin.H{"message": "删除成功", "affected": affected})
}

// 导出流量日志
func exportTrafficLogsHandler(c *gin.Context) {
	startTime := c.Query("start_time")
	endTime := c.Query("end_time")

	where := "1=1"
	args := []interface{}{}

	if startTime != "" {
		where += " AND created_at >= ?"
		args = append(args, startTime)
	}
	if endTime != "" {
		where += " AND created_at <= ?"
		args = append(args, endTime)
	}

	rows, err := db.Query(`
        SELECT domain, path, method, status_code, client_ip, user_agent, referer, 
               request_size, response_size, response_time, cache_status, created_at
        FROM traffic_logs 
        WHERE `+where+`
        ORDER BY created_at DESC
    `, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("查询失败: %v", err)})
		return
	}
	defer rows.Close()

	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", "attachment; filename=traffic_logs.csv")

	writer := csv.NewWriter(c.Writer)
	defer writer.Flush()

	// 写入表头
	writer.Write([]string{"域名", "路径", "方法", "状态码", "客户端IP", "User-Agent", "Referer",
		"请求大小", "响应大小", "响应时间(ms)", "缓存状态", "创建时间"})

	// 写入数据
	for rows.Next() {
		var log TrafficLog
		err := rows.Scan(&log.Domain, &log.Path, &log.Method, &log.StatusCode,
			&log.ClientIP, &log.UserAgent, &log.Referer, &log.RequestSize, &log.ResponseSize,
			&log.ResponseTime, &log.CacheStatus, &log.CreatedAt)
		if err == nil {
			writer.Write([]string{
				log.Domain,
				log.Path,
				log.Method,
				strconv.Itoa(log.StatusCode),
				log.ClientIP,
				log.UserAgent,
				log.Referer,
				strconv.FormatInt(log.RequestSize, 10),
				strconv.FormatInt(log.ResponseSize, 10),
				strconv.FormatInt(log.ResponseTime, 10),
				log.CacheStatus,
				log.CreatedAt.Format("2006-01-02 15:04:05"),
			})
		}
	}
}

// ------------------- 获取当前连接列表 -------------------
func getCurrentConnectionsList() ([]ConnectionInfo, error) {
	var connections []ConnectionInfo

	// 读取TCP连接信息
	tcpFiles := []string{"/proc/net/tcp", "/proc/net/tcp6"}

	for _, file := range tcpFiles {
		content, err := ioutil.ReadFile(file)
		if err != nil {
			continue
		}

		lines := strings.Split(string(content), "\n")
		for i, line := range lines {
			if i == 0 || strings.TrimSpace(line) == "" {
				continue // 跳过标题行和空行
			}

			fields := strings.Fields(line)
			if len(fields) >= 4 {
				// 解析本地地址（格式为IP:PORT，十六进制）
				localAddr := fields[1]
				state := fields[3]

				// 提取端口号（十六进制转十进制）
				parts := strings.Split(localAddr, ":")
				if len(parts) == 2 {
					portHex := parts[1]
					port, err := strconv.ParseInt(portHex, 16, 32)
					if err == nil {
						// 只关注80和443端口
						if port == 80 || port == 443 {
							connections = append(connections, ConnectionInfo{
								Protocol:  "TCP",
								LocalPort: fmt.Sprintf("%d", port),
								State:     state,
							})
						}
					}
				}
			}
		}
	}

	return connections, nil
}

// ------------------- 获取监控历史数据接口 -------------------
type MonitorHistoryResponse struct {
	Timestamps  []string  `json:"timestamps"`
	CPUUsage    []float64 `json:"cpu_usage"`
	MemoryUsage []float64 `json:"memory_usage"`
	Connections []int     `json:"connections"`
}

// 简单的历史数据存储（生产环境建议使用数据库）
var (
	monitorHistory []SystemMonitorResponse
	historyMutex   sync.RWMutex
	maxHistorySize = 100
)

// ------------------- 监控历史记录工作器 -------------------
func startMonitorHistoryWorker() {
	ticker := time.NewTicker(30 * time.Second) // 每30秒记录一次
	defer ticker.Stop()

	for range ticker.C {
		stats := SystemMonitorResponse{
			PortStats:   getPortStats(),
			CPUStats:    getCPUStats(),
			MemoryStats: getMemoryStats(),
			Timestamp:   time.Now().Format("15:04:05"),
		}

		historyMutex.Lock()
		monitorHistory = append(monitorHistory, stats)
		if len(monitorHistory) > maxHistorySize {
			monitorHistory = monitorHistory[1:]
		}
		historyMutex.Unlock()
	}
}

// ------------------- 自定义规则管理 -------------------

// 自定义规则目录
const customRuleDir = "./ownrule"

// 自定义规则相关
type CustomRule struct {
	ID          string  `yaml:"id"`
	Name        string  `yaml:"name"`
	Description string  `yaml:"description"`
	Method      string  `yaml:"method"`
	Relation    string  `yaml:"relation"`
	Judges      []Judge `yaml:"judge"`
	Enabled     bool    `yaml:"enabled"`
}

// 自定义规则管理器
type CustomRuleManager struct {
	rules map[string]CustomRule // id -> rule
	mutex sync.RWMutex
}

var customRuleManager *CustomRuleManager

// 初始化自定义规则管理器
func initCustomRuleManager() {
	customRuleManager = &CustomRuleManager{
		rules: make(map[string]CustomRule),
	}

	// 启动时加载自定义规则
	loadCustomRules()
}

// 加载自定义规则
// ------------------- 修复加载自定义规则 -------------------
func loadCustomRules() {
	customRuleManager.mutex.Lock()
	defer customRuleManager.mutex.Unlock()

	// 确保目录存在
	if err := os.MkdirAll(customRuleDir, 0755); err != nil {
		stdlog.Printf("创建自定义规则目录失败: %v", err)
		return
	}

	// 读取目录下的所有JSON文件
	files, err := ioutil.ReadDir(customRuleDir)
	if err != nil {
		stdlog.Printf("读取自定义规则目录失败: %v", err)
		return
	}

	// 按文件名排序确保顺序
	sort.Slice(files, func(i, j int) bool {
		return files[i].Name() < files[j].Name()
	})

	for _, file := range files {
		if filepath.Ext(file.Name()) != ".yaml" {
			continue
		}

		filePath := filepath.Join(customRuleDir, file.Name())
		data, err := ioutil.ReadFile(filePath)
		if err != nil {
			stdlog.Printf("读取自定义规则文件失败 %s: %v", file.Name(), err)
			continue
		}

		var ruleJSON CustomRuleJSON
		if err := yaml.Unmarshal(data, &ruleJSON); err != nil {
			stdlog.Printf("解析自定义规则文件失败 %s: %v", file.Name(), err)
			continue
		}

		// 兼容性处理：如果 Judges 为空，尝试从 judge 字段读取
		if len(ruleJSON.Judges) == 0 {
			var tempMap map[string]interface{}
			if err := yaml.Unmarshal(data, &tempMap); err == nil {
				if judgeData, ok := tempMap["judge"]; ok {
					// 将 judge 数据转换为 JSON 再解析
					judgeBytes, _ := json.Marshal(judgeData)
					var judges []JudgeJSON
					if err := yaml.Unmarshal(judgeBytes, &judges); err == nil {
						ruleJSON.Judges = judges
						stdlog.Printf("从 judge 字段加载自定义规则: %s\n", file.Name())
					}
				}
			}
		}

		// 转换为运行时结构
		rule := CustomRule{
			ID:          ruleJSON.ID,
			Name:        ruleJSON.Name,
			Description: ruleJSON.Description,
			Method:      ruleJSON.Method,
			Relation:    ruleJSON.Relation,
			Enabled:     ruleJSON.Enabled,
			Judges:      make([]Judge, len(ruleJSON.Judges)),
		}

		// 预编译正则表达式
		for i, judgeJSON := range ruleJSON.Judges {
			judge := Judge{
				Position: judgeJSON.Position,
				Content:  judgeJSON.Content,
				Rix:      judgeJSON.Rix,
				Action:   judgeJSON.Action,
			}

			if judge.Rix != "" {
				regex, err := regexp.Compile(judge.Rix)
				if err != nil {
					stdlog.Printf("正则表达式编译失败 %s: %v", judge.Rix, err)
					continue
				}
				judge.regex = regex
			}

			rule.Judges[i] = judge
		}

		// 验证规则
		if err := validateCustomRule(rule); err != nil {
			stdlog.Printf("自定义规则验证失败 %s: %v", file.Name(), err)
			continue
		}

		customRuleManager.rules[rule.ID] = rule

		// 立即合并到主规则系统
		mergeCustomRuleToMain(rule)

		stdlog.Printf("加载自定义规则: %s (ID: %s)", rule.Name, rule.ID)
	}

	stdlog.Printf("加载了 %d 个自定义规则", len(customRuleManager.rules))
}

// 验证自定义规则格式
func validateCustomRule(rule CustomRule) error {
	if rule.ID == "" {
		return fmt.Errorf("规则ID不能为空")
	}
	if rule.Name == "" {
		return fmt.Errorf("规则名称不能为空")
	}
	if rule.Method == "" {
		return fmt.Errorf("规则方法不能为空")
	}
	if len(rule.Judges) == 0 {
		return fmt.Errorf("规则判断条件不能为空")
	}

	// 验证方法
	validMethods := map[string]bool{
		"GET": true, "POST": true, "PUT": true, "DELETE": true,
		"HEAD": true, "OPTIONS": true, "PATCH": true, "any": true,
	}
	if !validMethods[rule.Method] {
		return fmt.Errorf("无效的HTTP方法: %s", rule.Method)
	}

	// 验证关系
	if rule.Relation != "" && rule.Relation != "and" && rule.Relation != "or" {
		return fmt.Errorf("无效的关系类型: %s", rule.Relation)
	}

	// 验证判断条件
	validPositions := map[string]bool{
		"uri": true, "request_header": true, "request_body": true,
		"parameter_key": true, "parameter_value": true, "form_values": true,
	}
	for i, judge := range rule.Judges {
		if !validPositions[judge.Position] {
			return fmt.Errorf("判断条件 %d 位置无效: %s", i+1, judge.Position)
		}
		if judge.Content == "" && judge.Rix == "" {
			return fmt.Errorf("判断条件 %d 内容和正则表达式不能同时为空", i+1)
		}
		if judge.Rix != "" {
			if _, err := regexp.Compile(judge.Rix); err != nil {
				return fmt.Errorf("判断条件 %d 正则表达式无效: %v", i+1, err)
			}
		}
	}

	return nil
}

// 生成下一个规则ID
func generateNextRuleID() string {
	customRuleManager.mutex.RLock()
	defer customRuleManager.mutex.RUnlock()

	maxID := 0
	for id := range customRuleManager.rules {
		if num, err := strconv.Atoi(id); err == nil {
			if num > maxID {
				maxID = num
			}
		}
	}
	return fmt.Sprintf("%d", maxID+1)
}

// ------------------- 序列化用的 Judge 结构体 -------------------
type JudgeJSON struct {
	Position string `yaml:"position" binding:"required"`
	Content  string `yaml:"content"`
	Rix      string `yaml:"rix"`
	Action   string `yaml:"action"`
}

// ------------------- 自定义规则序列化结构 -------------------
type CustomRuleJSON struct {
	ID          string      `yaml:"id"`
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Method      string      `yaml:"method"`
	Relation    string      `yaml:"relation"`
	Judges      []JudgeJSON `yaml:"judges"`
	Enabled     bool        `yaml:"enabled"`
}

// 保存规则到文件
// ------------------- 修复保存规则到文件 -------------------
func saveRuleToFile(rule CustomRule) error {
	filePath := filepath.Join(customRuleDir, fmt.Sprintf("%s.yaml", rule.ID))

	// 手动构建 YAML，使用 judge 字段以保持一致性
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("id: \"%s\"\n", rule.ID))
	buf.WriteString(fmt.Sprintf("name: %s\n", rule.Name))
	if rule.Description != "" {
		buf.WriteString(fmt.Sprintf("description: %s\n", rule.Description))
	}
	buf.WriteString(fmt.Sprintf("method: %s \n", rule.Method))
	if rule.Relation != "" {
		buf.WriteString(fmt.Sprintf("relation: %s\n", rule.Relation))
	}
	buf.WriteString("judge:\n")

	for _, judge := range rule.Judges {
		buf.WriteString(fmt.Sprintf("    - position: %s\n", judge.Position))
		if judge.Content != "" {
			buf.WriteString(fmt.Sprintf("      content: %s\n", judge.Content))
		} else {
			buf.WriteString("      content: \"\"\n")
		}
		if judge.Rix != "" {
			buf.WriteString(fmt.Sprintf("      rix: %s\n", judge.Rix))
		} else {
			buf.WriteString("      rix: \"\"\n")
		}
		if judge.Action != "" {
			buf.WriteString(fmt.Sprintf("      action: %s\n", judge.Action))
		}
	}

	buf.WriteString(fmt.Sprintf("enabled: %v\n", rule.Enabled))

	if err := ioutil.WriteFile(filePath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("写入规则文件失败: %v", err)
	}

	return nil
}

// 删除规则文件
func deleteRuleFile(ruleID string) error {
	filePath := filepath.Join(customRuleDir, fmt.Sprintf("%s.yaml", ruleID))
	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("删除规则文件失败: %v", err)
	}
	return nil
}

// ------------------- 自定义规则API接口 -------------------

// 确保 AddCustomRuleRequest 结构体定义正确
type AddCustomRuleRequest struct {
	Name        string  `json:"name" binding:"required"`
	Description string  `json:"description"`
	Method      string  `json:"method" binding:"required"`
	Relation    string  `json:"relation" binding:"oneof=and or"`
	Judges      []Judge `json:"judges" binding:"required,min=1,dive"`
	Enabled     bool    `json:"enabled"`
}

// 添加自定义规则接口
// ------------------- 修复添加自定义规则接口 -------------------
func addCustomRuleHandler(c *gin.Context) {
	var req AddCustomRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 生成规则ID
	ruleID := generateNextRuleID()

	// 处理默认值并预编译正则
	for i := range req.Judges {
		if req.Judges[i].Action == "" {
			req.Judges[i].Action = "is"
		}
		// 预编译正则表达式
		if req.Judges[i].Rix != "" {
			regex, err := regexp.Compile(req.Judges[i].Rix)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": fmt.Sprintf("正则表达式编译失败: %v", err),
				})
				return
			}
			req.Judges[i].regex = regex
		}
	}
	var rule CustomRule

	if req.Method == "any" {
		rule = CustomRule{
			ID:          ruleID,
			Name:        req.Name,
			Description: req.Description,
			Method:      req.Method,
			Relation:    req.Relation,
			Judges:      req.Judges,
			Enabled:     req.Enabled,
		}
	} else {
		// 创建规则对象
		rule = CustomRule{
			ID:          ruleID,
			Name:        req.Name,
			Description: req.Description,
			Method:      strings.ToUpper(req.Method),
			Relation:    req.Relation,
			Judges:      req.Judges,
			Enabled:     req.Enabled,
		}
	}

	// 设置默认关系
	if rule.Relation == "" {
		rule.Relation = "and"
	}

	// 验证规则
	if err := validateCustomRule(rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 保存到文件
	if err := saveRuleToFile(rule); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 添加到内存
	customRuleManager.mutex.Lock()
	customRuleManager.rules[ruleID] = rule
	customRuleManager.mutex.Unlock()

	// 合并到主规则系统
	mergeCustomRuleToMain(rule)

	stdlog.Printf("自定义规则添加成功: %s (ID: %s)", rule.Name, rule.ID)

	c.JSON(http.StatusOK, gin.H{
		"message": "自定义规则添加成功",
		"rule_id": ruleID,
		"rule":    rule,
	})
}

// 合并自定义规则到主规则系统
func mergeCustomRuleToMain(customRule CustomRule) {
	// 转换为主规则格式
	mainRule := Rule{
		ID:          customRule.ID,
		Name:        customRule.Name,
		Description: customRule.Description,
		Method:      customRule.Method,
		Relation:    customRule.Relation,
		Judges:      customRule.Judges,
		Enabled:     customRule.Enabled,
	}

	// 添加到主规则系统
	if _, exists := RULES[mainRule.Method]; !exists {
		RULES[mainRule.Method] = []Rule{}
	}

	// 检查是否已存在
	for i, existingRule := range RULES[mainRule.Method] {
		if existingRule.ID == mainRule.ID {
			RULES[mainRule.Method][i] = mainRule
			return
		}
	}

	// 添加新规则
	RULES[mainRule.Method] = append(RULES[mainRule.Method], mainRule)
}

// 获取自定义规则列表接口
func getCustomRulesHandler(c *gin.Context) {
	customRuleManager.mutex.RLock()
	defer customRuleManager.mutex.RUnlock()

	rules := make([]CustomRule, 0, len(customRuleManager.rules))
	for _, rule := range customRuleManager.rules {
		rules = append(rules, rule)
	}

	// 按ID排序
	sort.Slice(rules, func(i, j int) bool {
		id1, _ := strconv.Atoi(rules[i].ID)
		id2, _ := strconv.Atoi(rules[j].ID)
		return id1 < id2
	})

	c.JSON(http.StatusOK, gin.H{
		"rules": rules,
		"count": len(rules),
	})
}

// 更新自定义规则请求
type UpdateCustomRuleRequest struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Method      string  `json:"method"`
	Relation    string  `json:"relation" binding:"oneof=and or"`
	Judges      []Judge `json:"judge"`
	Enabled     *bool   `json:"enabled"`
}

// 更新自定义规则接口
// ------------------- 修复更新自定义规则接口 -------------------
// ------------------- 修复更新自定义规则接口 -------------------
func updateCustomRuleHandler(c *gin.Context) {
	ruleID := c.Param("id")

	// 使用更灵活的结构来解析请求
	var req map[string]interface{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	customRuleManager.mutex.Lock()
	defer customRuleManager.mutex.Unlock()

	// 检查规则是否存在
	existingRule, ruleExists := customRuleManager.rules[ruleID]
	if !ruleExists {
		c.JSON(http.StatusNotFound, gin.H{"error": "规则不存在"})
		return
	}

	// 更新字段 - 处理字段名称不一致的问题
	if name, ok := req["name"].(string); ok && name != "" {
		existingRule.Name = name
	}

	if description, ok := req["description"].(string); ok {
		existingRule.Description = description
	}

	if method, ok := req["method"].(string); ok && method != "" {
		existingRule.Method = strings.ToUpper(method)
	}

	if relation, ok := req["relation"].(string); ok && relation != "" {
		existingRule.Relation = relation
	}

	// 处理 judges/judge 字段（前端可能使用任意一个）
	var judgesData interface{}
	var judgesExists bool

	if judgesData, judgesExists = req["judges"]; !judgesExists {
		// 如果 judges 不存在，尝试使用 judge
		if judgeData, judgeExists := req["judge"]; judgeExists {
			judgesData = judgeData
			judgesExists = true
		}
	}

	if judgesExists && judgesData != nil {
		judgesBytes, err := json.Marshal(judgesData)
		if err == nil {
			var judges []Judge
			if err := json.Unmarshal(judgesBytes, &judges); err == nil {
				existingRule.Judges = judges

				// 预编译新的正则表达式
				for i := range existingRule.Judges {
					if existingRule.Judges[i].Rix != "" {
						regex, err := regexp.Compile(existingRule.Judges[i].Rix)
						if err != nil {
							c.JSON(http.StatusBadRequest, gin.H{
								"error": fmt.Sprintf("正则表达式编译失败: %v", err),
							})
							return
						}
						existingRule.Judges[i].regex = regex
					}
				}
			}
		}
	}

	if enabled, ok := req["enabled"].(bool); ok {
		existingRule.Enabled = enabled
	}

	// 验证规则
	if err := validateCustomRule(existingRule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 保存到文件
	if err := saveRuleToFile(existingRule); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 更新内存中的规则
	customRuleManager.rules[ruleID] = existingRule

	// 更新主规则系统
	mergeCustomRuleToMain(existingRule)

	stdlog.Printf("自定义规则更新成功: %s (ID: %s)", existingRule.Name, ruleID)

	c.JSON(http.StatusOK, gin.H{
		"message": "自定义规则更新成功",
		"rule":    existingRule,
	})
}

// 删除自定义规则接口
func deleteCustomRuleHandler(c *gin.Context) {
	ruleID := c.Param("id")

	customRuleManager.mutex.Lock()
	defer customRuleManager.mutex.Unlock()

	// 检查规则是否存在
	rule, exists := customRuleManager.rules[ruleID]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "规则不存在"})
		return
	}

	// 删除文件
	if err := deleteRuleFile(ruleID); err != nil {
		if !os.IsNotExist(err) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	// 从内存中删除
	delete(customRuleManager.rules, ruleID)

	// 从主规则系统中删除
	removeCustomRuleFromMain(ruleID)

	stdlog.Printf("自定义规则删除成功: %s (ID: %s)", rule.Name, ruleID)

	c.JSON(http.StatusOK, gin.H{
		"message": "自定义规则删除成功",
		"rule_id": ruleID,
	})
}

// 从主规则系统中移除自定义规则
func removeCustomRuleFromMain(ruleID string) {
	for method, rules := range RULES {
		for i, rule := range rules {
			if rule.ID == ruleID {
				RULES[method] = append(rules[:i], rules[i+1:]...)
				break
			}
		}
	}
}

// ------------------- 自定义规则状态切换接口 -------------------
type ToggleCustomRuleRequest struct {
	Enabled bool `json:"enabled"`
}

func toggleCustomRuleHandler(c *gin.Context) {
	ruleID := c.Param("id")

	var req ToggleCustomRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	customRuleManager.mutex.Lock()
	defer customRuleManager.mutex.Unlock()

	// 检查规则是否存在
	rule, exists := customRuleManager.rules[ruleID]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "规则不存在"})
		return
	}

	// 更新启用状态
	rule.Enabled = req.Enabled
	customRuleManager.rules[ruleID] = rule

	// 保存到文件
	if err := saveRuleToFile(rule); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 更新主规则系统
	mergeCustomRuleToMain(rule)

	status := "启用"
	if !req.Enabled {
		status = "禁用"
	}

	stdlog.Printf("自定义规则%s: %s (ID: %s)", status, rule.Name, ruleID)

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("规则%s成功", status),
		"enabled": req.Enabled,
	})
}

// 导出自定义规则接口
func exportCustomRulesHandler(c *gin.Context) {
	customRuleManager.mutex.RLock()
	defer customRuleManager.mutex.RUnlock()

	// 创建ZIP文件
	c.Header("Content-Type", "application/zip")
	c.Header("Content-Disposition", "attachment; filename=custom_rules_backup.zip")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")

	zipWriter := zip.NewWriter(c.Writer)
	defer zipWriter.Close()

	for _, rule := range customRuleManager.rules {
		// 创建规则文件
		ruleFile, err := zipWriter.Create(fmt.Sprintf("%s.json", rule.ID))
		if err != nil {
			stdlog.Printf("创建ZIP条目失败: %v", err)
			continue
		}

		data, err := json.MarshalIndent(rule, "", "  ")
		if err != nil {
			stdlog.Printf("序列化规则失败: %v", err)
			continue
		}

		if _, err := ruleFile.Write(data); err != nil {
			stdlog.Printf("写入ZIP条目失败: %v", err)
		}
	}

	stdlog.Printf("导出了 %d 个自定义规则", len(customRuleManager.rules))
}

// 导入自定义规则接口
func importCustomRulesHandler(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请选择要导入的文件"})
		return
	}

	if filepath.Ext(file.Filename) != ".zip" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "只支持ZIP格式的导入文件"})
		return
	}

	// 打开上传的文件
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "打开上传文件失败"})
		return
	}
	defer src.Close()

	// 读取ZIP文件
	fileData, err := ioutil.ReadAll(src)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取上传文件失败"})
		return
	}

	zipReader, err := zip.NewReader(bytes.NewReader(fileData), int64(len(fileData)))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的ZIP文件"})
		return
	}

	customRuleManager.mutex.Lock()
	defer customRuleManager.mutex.Unlock()

	importedCount := 0
	for _, zipFile := range zipReader.File {
		if filepath.Ext(zipFile.Name) != ".json" {
			continue
		}

		// 读取规则文件
		rc, err := zipFile.Open()
		if err != nil {
			stdlog.Printf("打开ZIP条目失败 %s: %v", zipFile.Name, err)
			continue
		}

		data, err := ioutil.ReadAll(rc)
		rc.Close()

		if err != nil {
			stdlog.Printf("读取ZIP条目失败 %s: %v", zipFile.Name, err)
			continue
		}

		var rule CustomRule
		if err := json.Unmarshal(data, &rule); err != nil {
			stdlog.Printf("解析规则失败 %s: %v", zipFile.Name, err)
			continue
		}

		// 验证规则
		if err := validateCustomRule(rule); err != nil {
			stdlog.Printf("规则验证失败 %s: %v", zipFile.Name, err)
			continue
		}

		// 预编译正则表达式
		for i := range rule.Judges {
			if rule.Judges[i].Rix != "" {
				rule.Judges[i].regex, _ = regexp.Compile(rule.Judges[i].Rix)
			}
		}

		// 保存到文件系统
		if err := saveRuleToFile(rule); err != nil {
			stdlog.Printf("保存规则失败 %s: %v", rule.ID, err)
			continue
		}

		// 添加到内存
		customRuleManager.rules[rule.ID] = rule

		// 合并到主规则系统
		mergeCustomRuleToMain(rule)

		importedCount++
		stdlog.Printf("导入自定义规则: %s (ID: %s)", rule.Name, rule.ID)
	}

	c.JSON(http.StatusOK, gin.H{
		"message":        "自定义规则导入成功",
		"imported_count": importedCount,
	})
}

// 重新加载自定义规则接口
func reloadCustomRulesHandler(c *gin.Context) {
	// 清空当前规则
	customRuleManager.mutex.Lock()
	customRuleManager.rules = make(map[string]CustomRule)
	customRuleManager.mutex.Unlock()

	// 重新加载
	loadCustomRules()

	// 重新合并到主规则系统
	customRuleManager.mutex.RLock()
	for _, rule := range customRuleManager.rules {
		mergeCustomRuleToMain(rule)
	}
	customRuleManager.mutex.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"message": "自定义规则重新加载成功",
		"count":   len(customRuleManager.rules),
	})
}

// ------------------- 删除单个缓存文件 -------------------
func deleteSingleCacheFile(cacheKey string) bool {
	if !staticCacheConfig.Enable {
		return false
	}

	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	if cachedFile, exists := fileCache[cacheKey]; exists {
		// 从内存缓存中移除
		currentCacheSize -= cachedFile.Size
		delete(fileCache, cacheKey)

		stdlog.Printf("单个缓存文件已删除: %s, 释放大小: %.2f KB",
			cacheKey, float64(cachedFile.Size)/1024)
		return true
	}

	return false
}

// ------------------- 删除单个缓存文件请求 -------------------
type DeleteCacheFileRequest struct {
	File string `json:"file" binding:"required"`
}

// ------------------- 删除单个缓存文件接口 -------------------
func deleteCacheFileHandler(c *gin.Context) {
	var req DeleteCacheFileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	cacheKey := req.File
	if cacheKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缓存文件键不能为空"})
		return
	}

	deleted := deleteSingleCacheFile(cacheKey)
	if !deleted {
		c.JSON(http.StatusNotFound, gin.H{"error": "缓存文件不存在"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "缓存文件删除成功",
		"file":    cacheKey,
	})
}

// ------------------- 获取监控历史接口 -------------------
func getMonitorHistoryHandler(c *gin.Context) {
	historyMutex.RLock()
	defer historyMutex.RUnlock()

	var response MonitorHistoryResponse

	for _, record := range monitorHistory {
		response.Timestamps = append(response.Timestamps, record.Timestamp)

		// 解析CPU使用率
		cpuUsage, _ := strconv.ParseFloat(strings.TrimSuffix(record.CPUStats.UsagePercent, "%"), 64)
		response.CPUUsage = append(response.CPUUsage, cpuUsage)

		// 解析内存使用率
		memUsage, _ := strconv.ParseFloat(strings.TrimSuffix(record.MemoryStats.UsagePercent, "%"), 64)
		response.MemoryUsage = append(response.MemoryUsage, memUsage)

		response.Connections = append(response.Connections, record.PortStats.TotalConnections)
	}

	c.JSON(http.StatusOK, response)
}

// ------------------- 获取设置接口 -------------------
// ------------------- 获取设置接口 -------------------
func getSettingsHandler(c *gin.Context) {
	settings := SystemSettings{
		EnableAntiDevTools:  EnableAntiDevTools,
		EnableJSObfuscation: EnableJSObfuscation, // 新增：返回JS混淆设置
		RuleMatchRate:       RuleMatchRate,
		Base64Depth:         maxDepth,
		URLDepth:            maxUrlDepth,
	}

	c.JSON(http.StatusOK, gin.H{
		"settings": settings,
	})
}

func ReadConfig() {
	confFile, err := os.ReadFile("conf.yaml")
	if err != nil {
		panic(fmt.Errorf("读取 conf.yaml 失败: %v", err))
	}

	if err := yaml.Unmarshal(confFile, &cfg); err != nil {
		panic(fmt.Errorf("解析 conf.yaml 失败: %v", err))
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

	password = "fox"

	// 创建蓝色输出
	fmt.Print("\033[H\033[2J")
	fmt.Println("------------------------账户信息---------------------------")
	blue := color.New(color.FgHiBlue).SprintFunc()
	fmt.Printf("账户密码为: %s:%s\n\n\n\n\n", blue(username), blue(password))
	fmt.Println("-----------------------------------------------------------")
}

func main() {

	debug.SetMaxThreads(10000)

	setAdmin()
	ReadConfig()
	initDb()
	readRule()
	readWafHtml()
	readBase64()
	readGinHtml()

	// 初始化自定义规则管理器
	initCustomRuleManager()

	// 初始化静态文件缓存
	initStaticCache()

	// 初始化CC管理器
	initCCManager()

	// 初始化端口统计
	initPortStats()

	go startMonitorHistoryWorker()

	// 启动流量记录工作器
	go trafficLogWorker()

	go statsPrinter()
	go StartGinAPI()
	go startHealthChecker()
	ReverseProxy()
}
