package tools

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"regexp"
	"fmt"
)


func DecodeBase64InRequest(req *http.Request) (*http.Request, error) {
	// 匹配常见 Base64 字符串（长度≥8，避免误判）
	base64Regex := regexp.MustCompile(`(?:[A-Za-z0-9+/]{8,}={0,2})`)

	// === 1. 处理 URL Query ===
	newURL := *req.URL // 拷贝 URL
	query := newURL.Query()
	changed := false

	for key, values := range query {
		for i, v := range values {
			if base64Regex.MatchString(v) {
				fmt.Println("检测到 Base64 URL 参数:", v) // 调试输出
				decoded, err := base64.StdEncoding.DecodeString(v)
				if err == nil {
					values[i] = string(decoded)
					changed = true
				}
			}
		}
		query[key] = values
	}
	if changed {
		newURL.RawQuery = query.Encode()
	}

	// === 2. 处理 Body ===
	var newBody io.ReadCloser
	if req.Body != nil {
		bodyBytes, _ := io.ReadAll(req.Body)
		_ = req.Body.Close()

		bodyStr := string(bodyBytes)
		if base64Regex.MatchString(bodyStr) {
			fmt.Println("检测到 Base64 Body:", bodyStr) // 调试输出
			decoded, err := base64.StdEncoding.DecodeString(bodyStr)
			if err == nil {
				newBody = io.NopCloser(bytes.NewReader(decoded))
				changed = true
			} else {
				newBody = io.NopCloser(bytes.NewReader(bodyBytes))
			}
		} else {
			newBody = io.NopCloser(bytes.NewReader(bodyBytes))
		}
	} else {
		newBody = nil
	}

	// === 3. 处理 Header ===
	newHeader := make(http.Header)
	for k, vals := range req.Header {
		for _, v := range vals {
			if base64Regex.MatchString(v) {
				fmt.Println("检测到 Base64 Header:", v) // 调试输出
				decoded, err := base64.StdEncoding.DecodeString(v)
				if err == nil {
					newHeader.Add(k, string(decoded))
					changed = true
					continue
				}
			}
			newHeader.Add(k, v)
		}
	}

	// 如果没有变化就返回原始请求
	if !changed {
		// 把 body 复位
		if newBody != nil {
			req.Body = newBody
		}
		return req, nil
	}

	// === 4. 重新构建新的请求 ===
	newReq := req.Clone(req.Context())
	newReq.URL = &newURL
	newReq.Body = newBody
	newReq.Header = newHeader

	return newReq, nil
}
