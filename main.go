package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	username = flag.String("u", "", "Username")
	password = flag.String("p", "", "Password")
	server   = flag.String("s", "202.204.67.15", "Server IP")
	acid     = flag.String("ac", "23", "AC ID")
)

// 深澜专用 Base64 字典
const srunAlphabet = "LVoJPiCN2R8G90yg+hmFzDj6S5E4Wl1eMMcXkT7u_nApqrbsB3IdhkaQZtxEwY"

func main() {
	flag.Parse()
	if *username == "" || *password == "" || *server == "" {
		fmt.Println("Usage: -u <user> -p <pass> -s <server_ip> [-ac <ac_id>]")
		return
	}

	fmt.Printf("Target: %s (AC_ID: %s)\n", *server, *acid)

	// 1. 获取 Token (Challenge)
	token, ip := getChallenge(*server, *username)
	if token == "" {
		fmt.Println("Fatal: Failed to get token.")
		return
	}
	fmt.Printf("Token: %s, IP: %s\n", token, ip)

	// 2. 密码加密逻辑 (V1.18 核心)
	// URL 和 Info 内部都使用 HMAC-MD5
	hmd5 := hmacMd5(*password, token)

	// 3. 构造 Info JSON
	// 关键：password 字段使用 hmd5，而不是纯 md5
	infoData := map[string]string{
		"username": *username,
		"password": hmd5,
		"ip":       ip,
		"acid":     *acid,
		"enc_ver":  "srun_bx1",
	}
	infoJSON, _ := json.Marshal(infoData)
	
	// 4. 加密 Info (使用 sencode + 自定义 Base64)
	// 格式固定为 {SRBX1} + 密文
	info := "{SRBX1}" + xEncode(string(infoJSON), token)

	// 5. 计算 chksum
	// 拼接顺序严格：token + username + token + hmd5 + token + acid + token + ip + token + n + token + type + token + info
	chkStr := token + *username + token + hmd5 + token + *acid + token + ip + token + "200" + token + "1" + token + info
	chksum := sha1Str(chkStr)

	// 6. 构造请求
	loginUrl := fmt.Sprintf("http://%s/cgi-bin/srun_portal", *server)
	timestamp := time.Now().UnixNano() / 1e6
	callback := fmt.Sprintf("jQuery%d_%d", timestamp, timestamp-500)

	params := url.Values{}
	params.Set("callback", callback)
	params.Set("action", "login")
	params.Set("username", *username)
	params.Set("password", "{MD5}"+hmd5) // URL 中需要 {MD5} 前缀
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
	fmt.Println("Sending login request...")

	// 7. 发送
	client := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequest("GET", fullUrl, nil)
	// 伪造 UA 非常重要
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Network Error: %v\n", err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	
	respStr := string(body)
	fmt.Println("Response:", respStr)

	if strings.Contains(respStr, "\"error\":\"ok\"") {
		fmt.Println("✅ Login Successful!")
	} else {
		fmt.Println("❌ Login Failed. Check parameters.")
	}
}

// ================== 核心加密算法实现 ==================

// getChallenge 获取 Token 和 IP
func getChallenge(server, username string) (string, string) {
	ts := time.Now().UnixNano() / 1e6
	u := fmt.Sprintf("http://%s/cgi-bin/get_challenge?callback=jQuery%d&username=%s&ip=0.0.0.0&_=%d", 
		server, ts, username, ts)
	
	resp, err := http.Get(u)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	content := string(body)

	// 正则提取 "challenge":"xxx" 和 "client_ip":"xxx"
	reToken := regexp.MustCompile(`"challenge":"(.*?)"`)
	reIp := regexp.MustCompile(`"client_ip":"(.*?)"`)

	tokenMatch := reToken.FindStringSubmatch(content)
	ipMatch := reIp.FindStringSubmatch(content)

	if len(tokenMatch) > 1 && len(ipMatch) > 1 {
		return tokenMatch[1], ipMatch[1]
	}
	return "", ""
}

// hmacMd5 计算 HMAC-MD5
func hmacMd5(password, token string) string {
	h := hmac.New(md5.New, []byte(token))
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

// sha1Str 计算 SHA1
func sha1Str(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

// xEncode 深澜核心加密函数 (对应 JS 中的 xEncode)
func xEncode(msg string, key string) string {
	if msg == "" {
		return ""
	}
	v := s(msg, true)
	k := s(key, false)

	if len(k) < 4 {
		newK := make([]uint32, 4)
		copy(newK, k)
		k = newK
	}

	n := len(v) - 1
	z := v[n]
	y := v[0]
	delta := uint32(0x9E3779B9)
	q := int(math.Floor(6 + 52/float64(n+1)))
	sum := uint32(0)

	for q > 0 {
		sum += delta
		e := (sum >> 2) & 3
		for p := 0; p < n; p++ {
			y = v[p+1]
			mx := (z>>5^y<<2) + (y>>3^z<<4) ^ (sum^y) + (k[p&3^e]^z)
			v[p] += mx
			z = v[p]
		}
		y = v[0]
		mx := (z>>5^y<<2) + (y>>3^z<<4) ^ (sum^y) + (k[n&3^e]^z)
		v[n] += mx
		z = v[n]
		q--
	}
	
	// 转回字节并进行自定义 Base64 编码
	return base64Srun(l(v, false))
}

// s 字符串转 uint32 数组 (Helper for xEncode)
func s(a string, b bool) []uint32 {
	lenA := len(a)
	var v []uint32
	// 初始长度估算
	vLen := (lenA + 3) / 4
	if b {
		v = make([]uint32, vLen+1) // 如果是 message，末尾多一位存长度
		v[vLen] = uint32(lenA)
	} else {
		v = make([]uint32, vLen)
	}
	
	for i := 0; i < lenA; i++ {
		v[i>>2] |= uint32(a[i]) << ((i & 3) * 8)
	}
	return v
}

// l uint32 数组转字节数组 (Helper for xEncode)
func l(a []uint32, b bool) []byte {
	lenA := len(a)
	lenV := lenA << 2
	if b {
		m := a[lenA-1]
		if int(m) < lenV-3 || int(m) > lenV {
			return nil
		}
		lenV = int(m)
	}
	
	res := make([]byte, lenV)
	for i := 0; i < lenV; i++ {
		res[i] = byte(a[i>>2] >> ((i & 3) * 8) & 0xff)
	}
	return res
}

// base64Srun 深澜自定义 Base64 编码
func base64Srun(input []byte) string {
	const pad = "="
	src := input
	dst := make([]byte, (len(src)+2)/3*4)
	
	// 映射表
	alpha := srunAlphabet
	
	di, si := 0, 0
	n := (len(src) / 3) * 3
	for si < n {
		val := uint(src[si+0])<<16 | uint(src[si+1])<<8 | uint(src[si+2])
		dst[di+0] = alpha[val>>18&0x3F]
		dst[di+1] = alpha[val>>12&0x3F]
		dst[di+2] = alpha[val>>6&0x3F]
		dst[di+3] = alpha[val&0x3F]
		si += 3
		di += 4
	}

	remain := len(src) - si
	if remain == 0 {
		return string(dst)
	}

	val := uint(src[si+0]) << 16
	if remain == 2 {
		val |= uint(src[si+1]) << 8
	}

	dst[di+0] = alpha[val>>18&0x3F]
	dst[di+1] = alpha[val>>12&0x3F]

	if remain == 2 {
		dst[di+2] = alpha[val>>6&0x3F]
	} else {
		dst[di+2] = pad[0]
	}
	dst[di+3] = pad[0]
	
	return string(dst)
}
