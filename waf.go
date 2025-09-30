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

// 从缓存获取文件
func getCachedFile(urlPath string) (*CachedFile, bool) {
    if !staticCacheConfig.Enable {
        return nil, false
    }
    
    cacheKey := generateCacheKey(urlPath)
    
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
func addToCache(urlPath string, content []byte, contentType string) {
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
        stdlog.Printf("缓存空间不足，跳过缓存: %s", urlPath)
        return
    }
    
    cacheKey := generateCacheKey(urlPath)
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

// 生成缓存键
func generateCacheKey(urlPath string) string {
    return fmt.Sprintf("url_%x", md5.Sum([]byte(urlPath)))
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

// 清理过期缓存
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
    
    if cleanedCount > 0 {
        stdlog.Printf("缓存清理完成: 清理了 %d 个文件, 释放了 %.2f MB", 
            cleanedCount, float64(cleanedSize)/(1024*1024))
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

// 检查是否为 HTML 内容
func isHTMLContent(contentType string) bool {
    if contentType == "" {
        return false
    }
    return strings.Contains(strings.ToLower(contentType), "text/html")
}

// 智能注入脚本（避免重复注入）
func injectAntiDevTools(htmlContent string) string {
    // 检查是否已经包含防开发者工具脚本
    if strings.Contains(htmlContent, "blockShortcuts") || 
       strings.Contains(htmlContent, "checkDebugger") {
        return htmlContent
    }
    
    // 在 </body> 前注入
    if strings.Contains(htmlContent, "</body>") {
        return strings.Replace(htmlContent, "</body>", antiDevToolsScript + "</body>", 1)
    }
    
    // 在 </html> 前注入
    if strings.Contains(htmlContent, "</html>") {
        return strings.Replace(htmlContent, "</html>", antiDevToolsScript + "</html>", 1)
    }
    
    // 直接追加
    return htmlContent + antiDevToolsScript
}















// ------------------- 修改主处理函数 -------------------
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

    // 先检查静态文件缓存
    if staticCacheConfig.Enable && req.Method == "GET" {
        if cachedFile, found := getCachedFile(req.URL.Path); found {
            // 设置缓存头
            w.Header().Set("Content-Type", cachedFile.ContentType)
            w.Header().Set("Content-Length", fmt.Sprintf("%d", cachedFile.Size))
            w.Header().Set("Cache-Control", "public, max-age=3600") // 1小时浏览器缓存
            w.Header().Set("X-Cache", "HIT")
            
            // 如果是 HTML 内容且启用了防开发者工具，需要重新注入脚本
            if EnableAntiDevTools && isHTMLContent(cachedFile.ContentType) {
                modifiedBody := injectAntiDevTools(string(cachedFile.Content))
                w.Header().Set("Content-Length", fmt.Sprintf("%d", len(modifiedBody)))
                w.WriteHeader(http.StatusOK)
                w.Write([]byte(modifiedBody))
            } else {
                w.WriteHeader(http.StatusOK)
                w.Write(cachedFile.Content)
            }
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

    // 处理响应体 - 支持防开发者工具注入
    if EnableAntiDevTools && isHTMLContent(contentType) && resp.StatusCode == 200 {
        // 读取响应体
        bodyBytes, err := io.ReadAll(resp.Body)
        if err != nil {
            stdlog.Printf("读取响应体失败: %v", err)
            w.WriteHeader(http.StatusInternalServerError)
            return
        }

        // 注入防开发者工具脚本
        modifiedBody := injectAntiDevTools(string(bodyBytes))

        // 更新 Content-Length
        w.Header().Set("Content-Length", fmt.Sprintf("%d", len(modifiedBody)))

        // 如果是静态文件且缓存启用，缓存修改后的内容
        if staticCacheConfig.Enable && req.Method == "GET" {
            if isCacheableStaticFile(req.URL.Path) {
                addToCache(req.URL.Path, []byte(modifiedBody), contentType)
                w.Header().Set("X-Cache", "MISS")
            }
        } else {
            w.Header().Set("X-Cache", "BYPASS")
        }

        // 设置状态码并写入修改后的响应
        w.WriteHeader(resp.StatusCode)
        _, err = w.Write([]byte(modifiedBody))
        if err != nil {
            stdlog.Printf("写入响应失败: %v", err)
        }

    } else {
        // 非 HTML 内容或功能关闭，直接处理
        if staticCacheConfig.Enable && req.Method == "GET" && resp.StatusCode == 200 {
            if isCacheableStaticFile(req.URL.Path) {
                // 读取响应体
                bodyBytes, err := io.ReadAll(resp.Body)
                if err == nil {
                    // 重新设置响应体
                    resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
                    
                    // 添加到缓存
                    actualContentType := resp.Header.Get("Content-Type")
                    if actualContentType == "" {
                        actualContentType = getContentType(req.URL.Path)
                    }
                    addToCache(req.URL.Path, bodyBytes, actualContentType)
                    
                    // 设置缓存头
                    w.Header().Set("X-Cache", "MISS")
                }
            }
        } else {
            w.Header().Set("X-Cache", "BYPASS")
        }

        // 设置状态码并直接拷贝响应体
        w.WriteHeader(resp.StatusCode)
        _, err = io.Copy(w, resp.Body)
        if err != nil {
            stdlog.Printf("拷贝响应体失败: %v", err)
        }
    }
}

// ------------------- 缓存管理 API -------------------
type CacheStatsResponse struct {
    Enable          bool   `json:"enable"`
    CacheHits       uint64 `json:"cache_hits"`
    CacheMisses     uint64 `json:"cache_misses"`
    HitRate         string `json:"hit_rate"`
    CurrentSize     string `json:"current_size"`
    MaxSize         string `json:"max_size"`
    CachedFiles     int    `json:"cached_files"`
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
    misses := atomic.LoadUint64(&cacheMisses)
    total := hits + misses
    hitRate := "0%"
    if total > 0 {
        hitRate = fmt.Sprintf("%.2f%%", float64(hits)/float64(total)*100)
    }
    
    stats := CacheStatsResponse{
        Enable:      staticCacheConfig.Enable,
        CacheHits:   hits,
        CacheMisses: misses,
        HitRate:     hitRate,
        CurrentSize: fmt.Sprintf("%.2f MB", float64(currentSize)/(1024*1024)),
        MaxSize:     fmt.Sprintf("%.2f MB", float64(staticCacheConfig.MaxCacheSize)/(1024*1024)),
        CachedFiles: cachedFiles,
    }
    
    c.JSON(http.StatusOK, stats)
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

    c.JSON(http.StatusOK, gin.H{
        "message": "登录成功",
        "token":   tokenString,
    })
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

        // 添加站点
        authGroup.POST("/api/site/add", addSiteHandler)
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


var login,loginError,notFound []byte

func readGinHtml() {
    login, _ = ioutil.ReadFile("./static/login.html")
    loginError, _ = ioutil.ReadFile("./static/loginError.html")
    notFound, _ = ioutil.ReadFile("./static/404.html")
}

// func StartGinAPI() {
// 	gin.SetMode(gin.ReleaseMode)
//     r := gin.Default()


// 	//---------ACL------------
// 	r.POST("/api/acl/rules", addACLRuleHandler)
//     r.GET("/api/acl/rules", getACLRulesHandler)
//     r.DELETE("/api/acl/rules/:id", deleteACLRuleHandler)

//     //-------------------缓存加速----------------------
//     r.GET("/api/cache/stats", getCacheStatsHandler)
//     r.POST("/api/cache/config", updateCacheConfigHandler)
//     r.POST("/api/cache/clear", clearCacheHandler)


// 	//waf

// 	//添加站点
//     r.POST("/api/site/add", addSiteHandler)
// 	//登录验证
// 	r.POST("/login", loginHandler)

// 	//登录页面
// 	r.GET(cfg.Secure, func(ctx *gin.Context) {
//     ctx.Header("Content-Type", "text/html; charset=utf-8")
//     ctx.String(http.StatusOK, string(login))
// 	})

//     //------------404-----------------------
//     r.NoRoute(func(ctx *gin.Context) {
//         ctx.Header("Content-Type", "text/html; charset=utf-8")
//         ctx.String(http.StatusNotFound, string(notFound))
//     })


//     stdlog.Println("Gin API 启动在 :8080")
//     if err := r.Run(":8080"); err != nil {
//         stdlog.Fatalf("Gin 启动失败: %v", err)
//     }
// }

// 定义三个变量，用于存储 HTML 内容


// wafDir 是 HTML 文件存放目录
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

    var rules []Rule
    if methodRules, ok := RULES[req.Method]; ok {
        rules = append(rules, methodRules...)
    }
    if anyRules, ok := RULES["any"]; ok {
        rules = append(rules, anyRules...)
    }

    if RuleMatchRate < 100 && RuleMatchRate > 0 && len(rules) > 0 {
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
    readGinHtml()

    // 初始化静态文件缓存
    initStaticCache()
	
	go statsPrinter()
	go StartGinAPI()
	ReverseProxy()
}