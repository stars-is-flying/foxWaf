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
	"sync"
	"net"
    "crypto/md5"
    "strconv"
    "encoding/csv"
    "sort"
	
	
    
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
    Relation    string  `json:"relation"`
	Judges      []Judge `json:"judge"`
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

// ------------------- 攻击日志查询参数 -------------------
type AttackLogQuery struct {
    Page      int       `form:"page" binding:"min=1"`
    PageSize  int       `form:"page_size" binding:"min=1,max=100"`
    Method    string    `form:"method"`
    RuleName  string    `form:"rule_name"`
    RuleID    string    `form:"rule_id"`
    StartTime string    `form:"start_time"`
    EndTime   string    `form:"end_time"`
    Search    string    `form:"search"`
}

// ------------------- 攻击日志响应结构 -------------------
type AttackLogResponse struct {
    ID           int       `json:"id"`
    Method       string    `json:"method"`
    URL          string    `json:"url"`
    Headers      string    `json:"headers"`
    Body         string    `json:"body"`
    RuleName     string    `json:"rule_name"`
    RuleID       string    `json:"rule_id"`
    MatchedValue string    `json:"matched_value"`
    ClientIP     string    `json:"client_ip"` // 新增
    CreatedAt    string    `json:"created_at"`
    
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
    TotalAttacks    int            `json:"total_attacks"`
    TodayAttacks    int            `json:"today_attacks"`
    TopRules        []RuleStat     `json:"top_rules"`
    TopMethods      []MethodStat   `json:"top_methods"`
    HourlyStats     []HourlyStat   `json:"hourly_stats"`
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


// ------------------- 删除攻击日志请求 -------------------
type DeleteAttackLogsRequest struct {
    IDs    []int  `json:"ids"`              // 指定ID删除
    Before string `json:"before"`           // 删除指定时间之前的记录
    All    bool   `json:"all"`              // 删除所有记录
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

    c.JSON(http.StatusOK, stats);
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
        &log.RuleName, &log.RuleID, &log.MatchedValue, &log.ClientIP,&log.CreatedAt,
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


//------------注入防开发者模式-----------------
var EnableAntiDevTools = true




// ------------------- 添加站点接口 -------------------
type AddSiteRequest struct {
    Name        string `json:"name" binding:"required"`
    Domain      string `json:"domain" binding:"required"`
    TargetURL   string `json:"target_url" binding:"required"`
    EnableHTTPS bool   `json:"enable_https"`
    CertName    string `json:"cert_name"` // 可选，自动生成自签名
}




//------------------------------静态缓存加速----------------------------------
// ------------------- 静态文件缓存配置 -------------------
type StaticCacheConfig struct {
    Enable          bool          // 是否开启静态缓存
    CacheDir        string        // 缓存目录
    MaxCacheSize    int64         // 最大缓存大小（字节）
    DefaultExpire   time.Duration // 默认缓存过期时间
    CleanupInterval time.Duration // 缓存清理间隔
}

type CachedFile struct {
    Content     []byte
    ContentType string
    Size        int64
    LastModified time.Time
    ExpireAt    time.Time
}

var staticCacheConfig = StaticCacheConfig{
    Enable:          true,                    // 默认开启
    CacheDir:        "./static_cache",        // 缓存目录
    MaxCacheSize:    100 * 1024 * 1024,       // 100MB
    DefaultExpire:   24 * time.Hour,          // 24小时
    CleanupInterval: 1 * time.Hour,           // 1小时清理一次
}

var (
    fileCache    = make(map[string]*CachedFile) // 内存缓存
    cacheMutex   sync.RWMutex
    currentCacheSize int64
    cacheHits   uint64
    cacheMisses uint64
)



//-------------------站点心跳------------------------
// 站点健康状态结构
type SiteHealth struct {
    SiteID    int    `json:"site_id"`
    Domain    string `json:"domain"`
    IsAlive   bool   `json:"is_alive"`
    Status    int    `json:"status"`
    Latency   int64  `json:"latency"` // 毫秒
    LastCheck string `json:"last_check"`
    ErrorMsg  string `json:"error_msg,omitempty"`
}

// 全局健康状态映射
var siteHealthMap = make(map[int]*SiteHealth)
var healthMutex sync.RWMutex

// 更健壮的健康检查函数，支持GET和HEAD方法
func checkSiteHealthEnhanced(site Site) *SiteHealth {
    health := &SiteHealth{
        SiteID:    site.ID,
        Domain:    site.Domain,
        LastCheck: time.Now().Format("2006-01-02 15:04:05"),
    }

    start := time.Now()
    
    // 直接使用 target_url
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
    if resp.StatusCode >= 200 && resp.StatusCode < 400 {
        health.IsAlive = true
        health.Status = resp.StatusCode
    } else {
        health.IsAlive = false
        health.Status = resp.StatusCode
        health.ErrorMsg = fmt.Sprintf("HTTP状态码: %d", resp.StatusCode)
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
    if resp.StatusCode >= 200 && resp.StatusCode < 400 {
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
    // 创建缓存目录
    if staticCacheConfig.Enable {
        err := os.MkdirAll(staticCacheConfig.CacheDir, 0755)
        if err != nil {
            stdlog.Printf("创建缓存目录失败: %v", err)
            staticCacheConfig.Enable = false
            return
        }
        
        // 启动定期清理协程
        go cacheCleanupWorker()
        
        stdlog.Printf("静态文件缓存已启用，缓存目录: %s", staticCacheConfig.CacheDir)
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
        ".css":  true,
        ".js":   true,
        ".png":  true,
        ".jpg":  true,
        ".jpeg": true,
        ".gif":  true,
        ".svg":  true,
        ".ico":  true,
        ".woff": true,
        ".woff2": true,
        ".ttf":  true,
        ".eot":  true,
        ".pdf":  true,
        ".txt":  true,
        ".xml":  true,
        ".json": true,
    }
    
    ext := strings.ToLower(filepath.Ext(path))
    return cacheableExts[ext]
}

// 获取内容类型
func getContentType(filename string) string {
    ext := strings.ToLower(filepath.Ext(filename))
    contentTypes := map[string]string{
        ".css":  "text/css; charset=utf-8",
        ".js":   "application/javascript",
        ".png":  "image/png",
        ".jpg":  "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif":  "image/gif",
        ".svg":  "image/svg+xml",
        ".ico":  "image/x-icon",
        ".woff": "font/woff",
        ".woff2": "font/woff2",
        ".ttf":  "font/ttf",
        ".eot":  "application/vnd.ms-fontobject",
        ".pdf":  "application/pdf",
        ".txt":  "text/plain; charset=utf-8",
        ".xml":  "application/xml",
        ".json": "application/json",
        ".html": "text/html; charset=utf-8",
        ".htm":  "text/html; charset=utf-8",
    }
    
    if contentType, ok := contentTypes[ext]; ok {
        return contentType
    }
    return "application/octet-stream"
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
        Content:     finalContent,
        ContentType: contentType,
        Size:        fileSize,
        LastModified: time.Now(),
        ExpireAt:    expireAt,
    }
    
    cacheMutex.Lock()
    // 如果已存在，先移除旧的
    if oldFile, exists := fileCache[cacheKey]; exists {
        currentCacheSize -= oldFile.Size
    }
    
    fileCache[cacheKey] = cachedFile
    currentCacheSize += fileSize
    cacheMutex.Unlock()
    
    // 异步保存到磁盘
    go saveToDiskCache(cacheKey, finalContent)
    
    stdlog.Printf("缓存添加成功: %s, 大小: %.2f KB", cacheKey, float64(fileSize)/1024)
}

// 从缓存移除
func removeFromCache(cacheKey string) {
    cacheMutex.Lock()
    defer cacheMutex.Unlock()
    
    if cachedFile, exists := fileCache[cacheKey]; exists {
        currentCacheSize -= cachedFile.Size
        delete(fileCache, cacheKey)
        
        // 同时删除磁盘缓存
        go deleteDiskCache(cacheKey)
    }
}

func generateCacheKey(urlPath string) string {
    hash := md5.Sum([]byte(urlPath))
    return fmt.Sprintf("cache_%x", hash)
}

// 保存到磁盘缓存
func saveToDiskCache(cacheKey string, content []byte) {
    cacheFile := filepath.Join(staticCacheConfig.CacheDir, cacheKey)
    err := ioutil.WriteFile(cacheFile, content, 0644)
    if err != nil {
        stdlog.Printf("保存磁盘缓存失败 %s: %v", cacheKey, err)
    }
}

// 从磁盘加载缓存
func loadFromDiskCache(cacheKey string) ([]byte, error) {
    cacheFile := filepath.Join(staticCacheConfig.CacheDir, cacheKey)
    return ioutil.ReadFile(cacheFile)
}

// 删除磁盘缓存
func deleteDiskCache(cacheKey string) {
    cacheFile := filepath.Join(staticCacheConfig.CacheDir, cacheKey)
    os.Remove(cacheFile)
}

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
    Enable          bool              `json:"enable"`
    CacheHits       uint64            `json:"cache_hits"`
    CacheMisses     uint64            `json:"cache_misses"`
    HitRate         string            `json:"hit_rate"`
    CurrentSize     string            `json:"current_size"`
    MaxSize         string            `json:"max_size"`
    CachedFiles     int               `json:"cached_files"`
    CacheItems      map[string]string `json:"cache_items,omitempty"`
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
func cleanupExpiredCache() {
    cacheMutex.Lock()
    defer cacheMutex.Unlock()
    
    now := time.Now()
    cleanedSize := int64(0)
    cleanedCount := 0
    
    for key, cachedFile := range fileCache {
        if now.After(cachedFile.ExpireAt) {
            currentCacheSize -= cachedFile.Size
            cleanedSize += cachedFile.Size
            cleanedCount++
            delete(fileCache, key)
            
            // 删除磁盘缓存
            go deleteDiskCache(key)
        }
    }
    
    // 如果还是超过限制，按LRU清理
    if currentCacheSize > staticCacheConfig.MaxCacheSize {
        stdlog.Printf("缓存仍然超过限制，执行LRU清理")
        cleanupLRUCache()
    }
    
    if cleanedCount > 0 {
        stdlog.Printf("缓存清理完成: 清理了 %d 个文件, 释放了 %.2f MB", 
            cleanedCount, float64(cleanedSize)/(1024*1024))
    }
}


// ------------------- 添加LRU缓存清理 -------------------
func cleanupLRUCache() {
    // 按最后修改时间排序
    type cacheItem struct {
        key    string
        file   *CachedFile
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
        
        // 删除磁盘缓存
        go deleteDiskCache(item.key)
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
        return strings.Replace(htmlContent, "</head>", antiDevToolsScript + "</head>", 1)
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
        return strings.Replace(htmlContent, "</html>", antiDevToolsScript + "</html>", 1)
    }
    
    // 直接追加到末尾
    return htmlContent + antiDevToolsScript
}

// ------------------- 修改主处理函数，修复缓存集成 -------------------
func handler(w http.ResponseWriter, req *http.Request) {
    atomic.AddUint64(&totalRequests, 1)

    // 查找目标站点
    host := req.Host
    var targetURL string
    var enableHTTPS bool
    var siteDomain string

    for _, site := range sites {
        if strings.EqualFold(site.Domain, host) && site.Status == 1 {
            targetURL = site.TargetURL
            enableHTTPS = site.EnableHTTPS
            siteDomain = site.Domain
            break
        }
    }

    if targetURL == "" {
        w.WriteHeader(http.StatusNotFound)
        w.Write([]byte(NotFoundPage))
        return
    }

    // 1. 先检查 ACL 规则
    blocked, aclRule := aclManager.checkACL(req, host)
    if blocked {
        atomic.AddUint64(&totalBlocked, 1)
        
        stdlog.Printf("ACL 拦截: %s %s, 规则: %s", 
            getClientIP(req), req.URL.Path, aclRule.Description)
            
        w.WriteHeader(http.StatusForbidden)
        w.Write([]byte(aclBlock))
        return
    }

    // 2. 再检查 WAF 规则
    attacked, log := isAttack(req)
    if attacked {
        atomic.AddUint64(&totalBlocked, 1)

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

    // 3. 检查静态文件缓存（修复缓存逻辑）
    if staticCacheConfig.Enable && req.Method == "GET" {
        cacheKey := generateCacheKey(req.URL.Path + "|" + siteDomain)
        if cachedFile, found := getCachedFile(cacheKey); found {
            // 设置缓存头
            w.Header().Set("Content-Type", cachedFile.ContentType)
            w.Header().Set("Content-Length", fmt.Sprintf("%d", cachedFile.Size))
            w.Header().Set("Cache-Control", "public, max-age=3600") // 1小时浏览器缓存
            w.Header().Set("X-Cache", "HIT")
            w.Header().Set("X-Cache-Key", cacheKey)
            
            // 写入缓存的响应
            w.WriteHeader(http.StatusOK)
            w.Write(cachedFile.Content)
            stdlog.Printf("缓存命中: %s%s", host, req.URL.Path)
            return
        }
    }

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
        cacheKey := generateCacheKey(req.URL.Path + "|" + siteDomain)
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
    Enable   *bool  `json:"enable"`
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
    }
    
    c.JSON(http.StatusOK, stats)
}

// ------------------- 缓存文件信息结构 -------------------
type CacheFileInfo struct {
    Key         string `json:"key"`
    Size        string `json:"size"`
    ContentType string `json:"content_type"`
    LastModified string `json:"last_modified"`
    ExpireAt    string `json:"expire_at"`
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
    
    var files []CacheFileInfo
    for key, cachedFile := range fileCache {
        fileInfo := CacheFileInfo{
            Key:         key,
            Size:        fmt.Sprintf("%.2f KB", float64(cachedFile.Size)/1024),
            ContentType: cachedFile.ContentType,
            LastModified: cachedFile.LastModified.Format("2006-01-02 15:04:05"),
            ExpireAt:    cachedFile.ExpireAt.Format("2006-01-02 15:04:05"),
        }
        files = append(files, fileInfo)
    }
    
    // 按最后修改时间排序
    sort.Slice(files, func(i, j int) bool {
        cacheMutex.RLock()
        defer cacheMutex.RUnlock()
        return fileCache[files[i].Key].LastModified.After(fileCache[files[j].Key].LastModified)
    })
    
    c.JSON(http.StatusOK, gin.H{
        "files": files,
        "count": len(files),
    })
}

// ------------------- 获取缓存文件内容接口 -------------------
func getCacheFileContentHandler(c *gin.Context) {
    cacheKey := c.Param("key")
    
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
        "message": "缓存配置更新成功",
        "enable":  staticCacheConfig.Enable,
        "max_size_mb": staticCacheConfig.MaxCacheSize / (1024 * 1024),
    })
}

// 清空缓存
func clearCacheHandler(c *gin.Context) {
    cacheMutex.Lock()
    fileCache = make(map[string]*CachedFile)
    currentCacheSize = 0
    cacheMutex.Unlock()
    
    // 清空磁盘缓存
    if staticCacheConfig.Enable {
        os.RemoveAll(staticCacheConfig.CacheDir)
        os.MkdirAll(staticCacheConfig.CacheDir, 0755)
    }
    
    atomic.StoreUint64(&cacheHits, 0)
    atomic.StoreUint64(&cacheMisses, 0)
    
    c.JSON(http.StatusOK, gin.H{"message": "缓存已清空"})
}














//------------------ACL------------------
type ACLRule struct {
    ID          int    `json:"id"`
    Type        string `json:"type"` // "global" 或 "host"
    Host        string `json:"host"` // 对于 host 类型有效
    RuleType    string `json:"rule_type"` // "ip", "country", "user_agent", "referer", "path"
    Pattern     string `json:"pattern"`
    Action      string `json:"action"` // "allow" 或 "block"
    Description string `json:"description"`
    Enabled     bool   `json:"enabled"`
}
type ACLManager struct {
    rules     []ACLRule
    ipRules   map[string][]ACLRule // IP 规则缓存
    regexCache map[string]*regexp.Regexp
    mutex     sync.RWMutex
}

var aclManager *ACLManager

func initACL() {
    aclManager = &ACLManager{
        rules:     make([]ACLRule, 0),
        ipRules:   make(map[string][]ACLRule),
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
        if strings.Contains(err.Error(), "doesn't exist") {
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
            id INT AUTO_INCREMENT PRIMARY KEY,
            type VARCHAR(20) NOT NULL DEFAULT 'global' COMMENT '规则类型: global, host',
            host VARCHAR(255) DEFAULT NULL COMMENT '针对的域名',
            rule_type VARCHAR(50) NOT NULL COMMENT '规则类型: ip, country, user_agent, referer, path',
            pattern TEXT NOT NULL COMMENT '匹配模式',
            action VARCHAR(10) NOT NULL COMMENT '动作: allow, block',
            description TEXT COMMENT '规则描述',
            enabled TINYINT(1) NOT NULL DEFAULT 1 COMMENT '是否启用',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_type (type),
            INDEX idx_host (host),
            INDEX idx_rule_type (rule_type),
            INDEX idx_enabled (enabled)
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
    aclManager.mutex.RLock()
    defer aclManager.mutex.RUnlock()

    c.JSON(http.StatusOK, gin.H{
        "rules": aclManager.rules,
        "count": len(aclManager.rules),
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
    TotalRequests    uint64  `json:"total_requests"`
    BlockedRequests  uint64  `json:"blocked_requests"`
    CacheHitRate     string  `json:"cache_hit_rate"`
    TotalRules       int     `json:"total_rules"`
    TotalSites       int     `json:"total_sites"`
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
        TotalRequests:    atomic.LoadUint64(&totalRequests),
        BlockedRequests:  atomic.LoadUint64(&totalBlocked),
        CacheHitRate:     hitRate,
        TotalRules:       totalRules,
        TotalSites:       len(sites),
    }

    c.JSON(http.StatusOK, stats)
}

// ------------------- 站点信息响应结构 -------------------
type SiteInfoResponse struct {
    ID          int    `json:"id"`
    Name        string `json:"name"`
    Domain      string `json:"domain"`
    TargetURL   string `json:"target_url"`
    EnableHTTPS bool   `json:"enable_https"`
    CertID      *int   `json:"cert_id,omitempty"`
    Status      int    `json:"status"`
    CreatedAt   string `json:"created_at"`
    UpdatedAt   string `json:"updated_at"`
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

        sitesResponse = append(sitesResponse, SiteInfoResponse{
            ID:          site.ID,
            Name:        site.Name,
            Domain:      site.Domain,
            TargetURL:   site.TargetURL,
            EnableHTTPS: site.EnableHTTPS,
            CertID:      certID,
            Status:      site.Status,
            CreatedAt:   site.CreatedAt,
            UpdatedAt:   site.UpdatedAt,
        })
    }

    c.JSON(http.StatusOK, gin.H{
        "sites": sitesResponse,
        "count": len(sitesResponse),
    })
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
        "message": "证书重新加载成功",
        "loaded_certificates": len(certificateMap),
    })
}

var login,loginError,notFound,panle []byte

func readGinHtml() {
    login, _ = ioutil.ReadFile("./static/login.html")
    loginError, _ = ioutil.ReadFile("./static/loginError.html")
    notFound, _ = ioutil.ReadFile("./static/404.html")
    panle, _ = ioutil.ReadFile("./static/panle.html")
}




// 在需要认证的路由中使用中间件
func StartGinAPI() {
    gin.SetMode(gin.ReleaseMode)
    r := gin.Default()

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
        //---------ACL------------
        authGroup.POST("/api/acl/rules", addACLRuleHandler)
        authGroup.GET("/api/acl/rules", getACLRulesHandler)
        authGroup.DELETE("/api/acl/rules/:id", deleteACLRuleHandler)

        //-------------------缓存加速----------------------
        authGroup.GET("/api/cache/stats", getCacheStatsHandler)
        authGroup.POST("/api/cache/config", updateCacheConfigHandler)
        authGroup.POST("/api/cache/clear", clearCacheHandler)
        authGroup.GET("/api/cache/stats/detail", getCacheStatsDetailHandler) // 新增详细统计
        authGroup.GET("/api/cache/files", getCacheFilesHandler)
        authGroup.GET("/api/cache/files/:key", getCacheFileContentHandler)

        // 添加站点
        authGroup.POST("/api/site/add", addSiteHandler)
        authGroup.GET("/api/sites", getSitesHandler)           
        authGroup.POST("/api/site/delete", deleteSiteHandler)
        authGroup.POST("/api/site/status", updateSiteStatusHandler)           // 新增：更新站点状态
        authGroup.POST("/api/site/https", updateSiteHTTPSHandler)             // 新增：更新HTTPS状态 

        // 证书管理
        authGroup.POST("/api/cert/upload", uploadCertHandler)              
        authGroup.POST("/api/site/update-cert", updateSiteCertHandler)     
        authGroup.POST("/api/cert/reload", reloadAllCertificatesHandler)  

        //// ------------------- waf信息统计 -------------------
        authGroup.GET("/api/stats", getStatsHandler)

        //// -------------------心跳------------------------------
        authGroup.GET("/health", getSiteHealthHandler)
        authGroup.GET("/health/:id", checkSingleSiteHealthHandler)

        // 攻击日志管理
        authGroup.GET("/api/attack/logs", getAttackLogsHandler)           // 获取攻击日志
        authGroup.GET("/api/attack/stats", getAttackStatsHandler)         // 获取攻击统计
        authGroup.DELETE("/api/attack/logs", deleteAttackLogsHandler)     // 删除攻击日志
        authGroup.GET("/api/attack/export", exportAttackLogsHandler)      // 导出攻击日志
        authGroup.GET("/api/attack/logs/:id", getAttackLogDetailHandler)  // 获取单个日志详情

         // 站点证书管理
        authGroup.POST("/api/site/add-with-cert", addSiteWithCertHandler)              // 添加站点带证书
        authGroup.GET("/api/site/:id/certificate", getSiteCertificateHandler)          // 获取站点证书信息
        authGroup.POST("/api/site/:id/renew-certificate", renewSiteCertificateHandler) // 重新生成证书
        authGroup.POST("/api/site/:id/replace-certificate", replaceSiteCertificateHandler) // 替换证书
        authGroup.POST("/api/site/:id/remove-certificate", removeSiteCertificateHandler) // 移除证


        // 在 authGroup 中添加设置相关的路由
        authGroup.GET("/api/settings", getSettingsHandler)
        authGroup.POST("/api/settings", updateSettingsHandler)
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


func readWafHtml() {
    interceptPage = loadWAFPage("intercept.html")
    NotFoundPage = loadWAFPage("notfound.html")
    proxyErrorPage = loadWAFPage("proxy_error.html")
	aclBlock = loadWAFPage("aclBlock.html")
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

    // 修复：如果规则匹配率为0，直接返回不拦截
    if RuleMatchRate == 0 {
        return false, nil
    }

    var rules []Rule
    if methodRules, ok := RULES[req.Method]; ok {
        rules = append(rules, methodRules...)
    }
    if anyRules, ok := RULES["any"]; ok {
        rules = append(rules, anyRules...)
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
        // 获取匹配结果
        matched, matchedValues := evaluateRule(rule, rawURL, head, body, paramValues, formValues, isBodyNull)
        
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
func evaluateRule(rule Rule, rawURL, head, body, paramValues, formValues string, isBodyNull bool) (bool, []string) {
    if len(rule.Judges) == 0 {
        return false, nil
    }
    
    var matchedValues []string
    var matchResults []bool
    
    // 评估每个judge
    for _, judge := range rule.Judges {
        var target string
        switch judge.Position {
        case "uri":
            target = rawURL
        case "request_header":
            target = head
        case "request_body":
            if isBodyNull {
                matchResults = append(matchResults, false)
                continue
            }
            target = body
        case "parameter_value":
            target = paramValues
        case "form_values":
            target = formValues
        default:
            matchResults = append(matchResults, false)
            continue
        }

        matchedStr := match(target, judge)
        if matchedStr != "" {
            matchResults = append(matchResults, true)
            matchedValues = append(matchedValues, matchedStr)
        } else {
            matchResults = append(matchResults, false)
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
    panic(fmt.Errorf("ping数据库失败: %w", err))
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
        client_ip VARCHAR(45),  -- 新增客户端IP字段，支持IPv6
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

	initACL()
    
    fmt.Println("ACL 管理器已初始化")

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
    Name        string `json:"name" binding:"required"`
    Domain      string `json:"domain" binding:"required"`
    TargetURL   string `json:"target_url" binding:"required"`
    EnableHTTPS bool   `json:"enable_https"`
    ValidDays   int    `json:"valid_days"`
    CertText    string `json:"cert_text"`
    KeyText     string `json:"key_text"`
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
        Name:        getString(req, "name"),
        Domain:      getString(req, "domain"),
        TargetURL:   getString(req, "target_url"),
        EnableHTTPS: getBool(req, "enable_https"),
        CertText:    getString(req, "cert_text"),
        KeyText:     getString(req, "key_text"),
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
    if addSiteReq.Name == "" || addSiteReq.Domain == "" || addSiteReq.TargetURL == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "name, domain, target_url 为必填字段"})
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
    insertSite := `INSERT INTO sites (name, domain, target_url, enable_https, cert_id, status) VALUES (?, ?, ?, ?, ?, ?)`
    result, err := db.Exec(insertSite, addSiteReq.Name, addSiteReq.Domain, addSiteReq.TargetURL, boolToInt(addSiteReq.EnableHTTPS), certID, 1)
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

    // 热更新内存 sites 列表
    newSite := Site{
        ID:          int(siteID), // 确保ID正确设置
        Name:        addSiteReq.Name,
        Domain:      addSiteReq.Domain,
        TargetURL:   addSiteReq.TargetURL,
        EnableHTTPS: addSiteReq.EnableHTTPS,
        Status:      1,
    }
    if certID != nil {
        newSite.CERTID = sql.NullInt64{Int64: certID.(int64), Valid: true}
    }
    sites = append(sites, newSite)

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

// ------------------- 证书信息结构 -------------------
type CertificateDetail struct {
    Exists        bool   `json:"exists"`
    Domain        string `json:"domain"`
    ValidFrom     string `json:"valid_from"`
    ValidTo       string `json:"valid_to"`
    Issuer        string `json:"issuer"`
    IsSelfSigned  bool   `json:"is_self_signed"`
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
type SystemSettings struct {
    EnableAntiDevTools bool `json:"enable_anti_devtools"`
    RuleMatchRate      int  `json:"rule_match_rate"`
    Base64Depth        int  `json:"base64_depth"`
    URLDepth           int  `json:"url_depth"`
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
    RuleMatchRate = settings.RuleMatchRate
    maxDepth = settings.Base64Depth
    maxUrlDepth = settings.URLDepth

    c.JSON(http.StatusOK, gin.H{
        "message": "系统设置更新成功",
        "settings": settings,
    })
}

// ------------------- 获取设置接口 -------------------
func getSettingsHandler(c *gin.Context) {
    settings := SystemSettings{
        EnableAntiDevTools: EnableAntiDevTools,
        RuleMatchRate:      RuleMatchRate,
        Base64Depth:        maxDepth,
        URLDepth:           maxUrlDepth,
    }

    c.JSON(http.StatusOK, gin.H{
        "settings": settings,
    })
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

    password = "fox"

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
    readGinHtml()

    // 初始化静态文件缓存
    initStaticCache()
	
	go statsPrinter()
	go StartGinAPI()
    go startHealthChecker()
	ReverseProxy()
}