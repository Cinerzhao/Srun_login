package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

// 已删除 "math/big" 这个多余的包

var (
	username = flag.String("u", "", "Username")
	password = flag.String("p", "", "Password")
	server   = flag.String("s", "", "Server IP")
	acid     = flag.String("ac", "23", "AC ID")
)

func main() {
	flag.Parse()
	if *username == "" || *password == "" || *server == "" {
		fmt.Println("Usage: -u <user> -p <pass> -s <server_ip> [-ac <ac_id>]")
		return
	}

	// 1. 获取 Token
	token, ip := getChallenge(*server, *username)
	if token == "" {
		fmt.Println("Failed to get token")
		return
	}
	fmt.Printf("Token: %s, IP: %s\n", token, ip)

	// 2. 密码加密 (标准 HMAC-MD5)
	// 尽管抓包显示 MD5，但 API 接口通常强制要求 HMAC
	hmd5 := hmacMd5(*password, token)

	// 3. 生成 Info (XEncode)
	infoJSON := fmt.Sprintf(`{"username":"%s","password":"%s","ip":"%s","acid":"%s","enc_ver":"srun_bx1"}`,
		*username, hmd5, ip, *acid)
	
	info := "{SRBX1}" + xEncode(infoJSON, token)

	// 4. 计算 Checksum
	chkStr := token + *username + token + hmd5 + token + *acid + token + ip + token + "200" + token + "1" + token + info
	chksum := sha1Str(chkStr)

	// 5. 发送请求
	loginUrl := fmt.Sprintf("http://%s/cgi-bin/srun_portal", *server)
	
	timestamp := time.Now().UnixNano() / 1e6
	callback := "jQuery" + strconv.FormatInt(timestamp, 10) + "_" + strconv.FormatInt(timestamp-500, 10)

	params := url.Values{}
	params.Set("callback", callback)
	params.Set("action", "login")
	params.Set("username", *username)
	params.Set("password", "{MD5}"+hmd5)
	params.Set("ac_id", *acid)
	params.Set("ip", ip)
	params.Set("chksum", chksum)
	params.Set("info", info)
	params.Set("n", "200")
	params.Set("type", "1")
	params.Set("os", "Windows 10")
	params.Set("name", "Windows")
	params.Set("double_stack", "0")
	params.Set("_", strconv.FormatInt(timestamp, 10))

	fullUrl := loginUrl + "?" + params.Encode()
	fmt.Println("Sending request...")

	client := &http.Client{}
	req, err := http.NewRequest("GET", fullUrl, nil)
	if err != nil {
		fmt.Println("Request error:", err)
		return
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Login failed:", err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	
	fmt.Println("Response:", string(body))
}

// === 核心算法 ===

func getChallenge(host, user string) (string, string) {
	timestamp := time.Now().UnixNano() / 1e6
	u := fmt.Sprintf("http://%s/cgi-bin/get_challenge?callback=jsonp&username=%s&ip=0.0.0.0&_=%d",
		host, user, timestamp)
	
	client := &http.Client{}
	r
