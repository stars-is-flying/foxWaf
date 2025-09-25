package main

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/gob"
    "encoding/hex"
    "encoding/json"   // ← 这里
    "fmt"
    "io"
    "os"
    "path/filepath"
    "regexp"          // ← 这里
    "strings"         // ← 这里
    "time"
)

// 规则缓存结构
type RuleCache struct {
	Rules    map[string][]Rule
	Version  string
	BuildTime time.Time
	Checksum string
}

// 加密密钥（使用SHA256哈希固定密钥）
var encryptionKey []byte

func init() {
	key := "Kali@123"
	hash := sha256.Sum256([]byte(key))
	encryptionKey = hash[:]
}


func CompileAndSaveRules() error {
	fmt.Println("开始编译规则...")
	startTime := time.Now()
	
	// 读取并编译规则
	ruleDir := "/rule_updated"
	rules := make(map[string][]Rule)
	
	err := filepath.WalkDir(ruleDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		
		if filepath.Ext(path) != ".json" {
			return nil
		}
		
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("读取文件失败: %s, 错误: %v", path, err)
		}
		
		if strings.HasPrefix(string(data), "[") {
			var ruleArray []Rule
			if err := json.Unmarshal(data, &ruleArray); err != nil {
				return fmt.Errorf("解析 JSON 数组失败: %s, 错误: %v", path, err)
			}
			for _, r := range ruleArray {
				compileRule(&r)
				rules[r.Method] = append(rules[r.Method], r)
			}
		} else {
			var r Rule
			if err := json.Unmarshal(data, &r); err != nil {
				return fmt.Errorf("解析 JSON 失败: %s, 错误: %v", path, err)
			}
			compileRule(&r)
			rules[r.Method] = append(rules[r.Method], r)
		}
		
		return nil
	})
	
	if err != nil {
		return err
	}
	
	// 创建缓存对象
	cache := RuleCache{
		Rules:     rules,
		Version:   "1.0",
		BuildTime: time.Now(),
	}
	
	// 计算校验和
	cache.Checksum = calculateChecksum(cache)
	
	// 保存加密缓存
	err = saveEncryptedCache(cache, "rules.cache")
	if err != nil {
		return err
	}
	
	// 统计信息
	total := 0
	for _, ruleList := range rules {
		total += len(ruleList)
	}
	
	elapsed := time.Since(startTime)
	fmt.Printf("规则编译完成！方法数: %d，总规则数: %d，耗时: %v\n", len(rules), total, elapsed)
	fmt.Printf("加密缓存已保存: rules.cache\n")
	
	return nil
}

// compileRule 编译单个规则（预编译正则表达式）
func compileRule(rule *Rule) {
	for i := range rule.Judges {
		if rule.Judges[i].Rix != "" {
			rule.Judges[i].regex, _ = regexp.Compile(rule.Judges[i].Rix)
		}
	}
}

// calculateChecksum 计算缓存校验和
func calculateChecksum(cache RuleCache) string {
	// 简单的校验和计算，用于验证数据完整性
	data := fmt.Sprintf("%v-%v", cache.Version, cache.BuildTime.Unix())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:16]) // 取前16字节
}

// saveEncryptedCache 保存加密的缓存文件
func saveEncryptedCache(cache RuleCache, filename string) error {
	// 序列化数据
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(cache); err != nil {
		return fmt.Errorf("序列化失败: %v", err)
	}
	
	// 加密数据
	encryptedData, err := encryptData(buffer.Bytes())
	if err != nil {
		return fmt.Errorf("加密失败: %v", err)
	}
	
	// 写入文件
	if err := os.WriteFile(filename, encryptedData, 0644); err != nil {
		return fmt.Errorf("写入文件失败: %v", err)
	}
	
	return nil
}

// encryptData AES加密数据
func encryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	
	// 创建GCM模式
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	// 生成随机nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	
	// 加密数据
	encrypted := gcm.Seal(nonce, nonce, data, nil)
	return encrypted, nil
}

// LoadEncryptedRules 从加密文件加载规则
func LoadEncryptedRules(filename string) error {
	fmt.Println("从加密缓存加载规则...")
	startTime := time.Now()
	
	// 检查缓存文件是否存在
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		fmt.Println("缓存文件不存在，需要重新编译规则")
		return CompileAndSaveRules()
	}
	
	// 读取加密文件
	encryptedData, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("读取缓存文件失败: %v", err)
	}
	
	// 解密数据
	decryptedData, err := decryptData(encryptedData)
	if err != nil {
		fmt.Printf("解密失败: %v，重新编译规则...\n", err)
		return CompileAndSaveRules()
	}
	
	// 反序列化
	var cache RuleCache
	buffer := bytes.NewBuffer(decryptedData)
	decoder := gob.NewDecoder(buffer)
	if err := decoder.Decode(&cache); err != nil {
		fmt.Printf("反序列化失败: %v，重新编译规则...\n", err)
		return CompileAndSaveRules()
	}
	
	// 验证校验和
	if cache.Checksum != calculateChecksum(cache) {
		fmt.Println("缓存校验失败，重新编译规则...")
		return CompileAndSaveRules()
	}
	
	// 加载到全局变量
	RULES = cache.Rules
	
	// 统计信息
	total := 0
	for _, ruleList := range RULES {
		total += len(ruleList)
	}
	
	elapsed := time.Since(startTime)
	fmt.Printf("规则加载完成！方法数: %d，总规则数: %d，耗时: %v\n", len(RULES), total, elapsed)
	
	return nil
}

// decryptData AES解密数据
func decryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("数据太短")
	}
	
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	
	return decrypted, nil
}