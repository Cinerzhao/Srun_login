package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

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

	// 1. 获取 Challenge (Token)
	token, ip := getChallenge(*server, *username)
	if token == "" {
		fmt.Println("Failed to get token")
		return
	}
	fmt.Printf("Token: %s, IP: %s\n", token, ip)

	// 2. 密码加密 (使用标准的 HMAC-MD5)
	// 即使你抓包看到的是 {MD5}，API 往往也接受并更喜欢 {MD5}HMAC
	hmd5 := hmacMd5(*password, token)

	// 3. 生成 Info (XEncode)
	// 标准 Srun 的 info 里的 JSON，密码字段放的是 HMAC-MD5 的值
	infoJSON := fmt.Sprintf(`{"username":"%s","password":"%s","ip":"%s","acid":"%s","enc_ver":"srun_bx1"}`,
		*username, hmd5, ip, *acid)
	
	info := "{SRBX1}" + xEncode(infoJSON, token)

	// 4. 计算 Checksum
	// 顺序：token + username + token + hmd5 + token + acid + token + ip + token + n + token + type + token + info
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
	params.Set("password", "{MD5}"+hmd5) // 这里发送 HMAC-MD5
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

// === 核心算法部分 ===

func getChallenge(host, user string) (string, string) {
	timestamp := time.Now().UnixNano() / 1e6
	u := fmt.Sprintf("http://%s/cgi-bin/get_challenge?callback=jsonp&username=%s&ip=0.0.0.0&_=%d",
		host, user, timestamp)
	
	client := &http.Client{}
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	
	resp, err := client.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	
	reToken := regexp.MustCompile(`"challenge":"(.*?)"`)
	reIP := regexp.MustCompile(`"client_ip":"(.*?)"`)
	
	t := reToken.FindStringSubmatch(s)
	i := reIP.FindStringSubmatch(s)
	
	if len(t) > 1 && len(i) > 1 {
		return t[1], i[1]
	}
	return "", ""
}

// 标准 Srun HMAC-MD5: Key 是 Token, Data 是 Password
func hmacMd5(password, token string) string {
	h := hmac.New(md5.New, []byte(token))
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

func sha1Str(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

// 标准 XEncode 算法 (移植自 srun-tool)
func xEncode(msg, key string) string {
	if msg == "" {
		return ""
	}
	pwd := sencode(msg, true)
	pwdk := sencode(key, false)
	
	if len(pwdk) < 4 {
		pwdk = make([]int64, 4)
	}
	
	n := len(pwd) - 1
	z := pwd[n]
	y := pwd[0]
	c := int64(0x9E3779B9)
	m := int64(0)
	e := int64(0)
	p := 0
	q := int64(6 + 52/(n+1))
	d := int64(0)
	
	for q > 0 {
		d = (d + c) & 0xFFFFFFFF
		e = (d >> 2) & 3
		for p = 0; p < n; p++ {
			y = pwd[p+1]
			m = (z>>5^y<<2) + (y>>3^z<<4) ^ (d^y) + (pwdk[p&3^int(e)]^z)
			pwd[p] = (pwd[p] + m) & 0xFFFFFFFF
			z = pwd[p]
		}
		y = pwd[0]
		m = (z>>5^y<<2) + (y>>3^z<<4) ^ (d^y) + (pwdk[p&3^int(e)]^z)
		pwd[n] = (pwd[n] + m) & 0xFFFFFFFF
		z = pwd[n]
		q--
	}
	
	l := len(pwd) * 4
	res := make([]byte, l)
	for i := 0; i < len(pwd); i++ {
		res[i*4] = byte(pwd[i] & 0xFF)
		res[i*4+1] = byte((pwd[i] >> 8) & 0xFF)
		res[i*4+2] = byte((pwd[i] >> 16) & 0xFF)
		res[i*4+3] = byte((pwd[i] >> 24) & 0xFF)
	}
	return base64Custom(res[0:l])
}

func sencode(a string, b bool) []int64 {
	c := len(a)
	var v []int64
	for i := 0; i < c; i += 4 {
		var t int64 = 0
		if i < c { t |= int64(a[i]) }
		if i+1 < c { t |= int64(a[i+1]) << 8 }
		if i+2 < c { t |= int64(a[i+2]) << 16 }
		if i+3 < c { t |= int64(a[i+3]) << 24 }
		v = append(v, t)
	}
	if b {
		v = append(v, int64(c))
	}
	return v
}

// Srun 使用的标准 Base64 字符集 (通常是标准表，但也可能有变种，这里用最标准的实现)
func base64Custom(input []byte) string {
	const encode = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	result := make([]byte, 0)
	val := int64(0)
	bits := 0
	for _, b := range input {
		val = (val << 8) | int64(b)
		bits += 8
		for bits >= 6 {
			result = append(result, encode[(val>>(bits-6))&0x3f])
			bits -= 6
		}
	}
	if bits > 0 {
		result = append(result, encode[(val<<(6-bits))&0x3f])
	}
	return string(result)
}

// 辅助：处理大数 (Srun 算法有时涉及无符号移位，Go 的 int64 够用了，但要注意逻辑)
// 上面的 xEncode 已经处理了 int64 的溢出逻辑 (& 0xFFFFFFFF)
// 为了确保万无一失，引入 math/big 并不是必须的，因为 Srun 算法是基于 C 的 32位整数溢出的。
// 上面的代码已经模拟了 32位行为。
