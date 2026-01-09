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

	// 1. 获取 Token
	token, ip := getChallenge(*server, *username)
	if token == "" {
		fmt.Println("Fatal: Failed to get token.")
		return
	}
	fmt.Printf("Token: %s, IP: %s\n", token, ip)

	// 2. 加密密码 (V1.18 标准: HMAC-MD5)
	hmd5 := hmacMd5(*password, token)

	// 3. 构造 Info JSON
	// 修正：Info 内部也必须使用 HMAC-MD5 (与 URL 参数一致，但不带 {MD5} 前缀)
	infoData := map[string]string{
		"username": *username,
		"password": hmd5, 
		"ip":       ip,
		"acid":     *acid,
		"enc_ver":  "srun_bx1",
	}
	infoJSON, _ := json.Marshal(infoData)
	fmt.Println("Info JSON:", string(infoJSON))

	// 4. 加密 Info (核心修复在 xEncode)
	info := "{SRBX1}" + xEncode(string(infoJSON), token)

	// 5. 计算 Checksum
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
	fmt.Println("Sending login request...")

	// 7. 发送
	client := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequest("GET", fullUrl, nil)
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
		fmt.Println("❌ Login Failed.")
	}
}

// ================== 核心算法 ==================

func getChallenge(server, username string) (string, string) {
	ts := time.Now().UnixNano() / 1e6
	u := fmt.Sprintf("http://%s/cgi-bin/get_challenge?callback=jQuery%d&username=%s&ip=0.0.0.0&_=%d", 
		server, ts, username, ts)
	
	resp, err := http.Get(u)
	if err != nil { return "", "" }
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	content := string(body)

	reToken := regexp.MustCompile(`"challenge":"(.*?)"`)
	reIp := regexp.MustCompile(`"client_ip":"(.*?)"`)
	tokenMatch := reToken.FindStringSubmatch(content)
	ipMatch := reIp.FindStringSubmatch(content)

	if len(tokenMatch) > 1 && len(ipMatch) > 1 {
		return tokenMatch[1], ipMatch[1]
	}
	return "", ""
}

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

// xEncode 核心修复：添加括号解决 Go/JS 运算符优先级差异
func xEncode(msg string, key string) string {
	if msg == "" { return "" }
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
		e := int((sum >> 2) & 3)
		for p := 0; p < n; p++ {
			y = v[p+1]
			// 核心修复：JS中 (A + B ^ C + D) 等价于 (A+B) ^ (C+D)
			// Go中必须显式加括号，否则是 ((A+B)^C)+D
			mx := ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (k[(p&3)^e] ^ z))
			v[p] += mx
			z = v[p]
		}
		y = v[0]
		// 核心修复：同上
		mx := ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (k[(n&3)^e] ^ z))
		v[n] += mx
		z = v[n]
		q--
	}
	return base64Srun(l(v, false))
}

func s(a string, b bool) []uint32 {
	lenA := len(a)
	var v []uint32
	vLen := (lenA + 3) / 4
	if b {
		v = make([]uint32, vLen+1)
		v[vLen] = uint32(lenA)
	} else {
		v = make([]uint32, vLen)
	}
	for i := 0; i < lenA; i++ {
		v[i>>2] |= uint32(a[i]) << ((i & 3) * 8)
	}
	return v
}

func l(a []uint32, b bool) []byte {
	lenA := len(a)
	lenV := lenA << 2
	if b {
		m := a[lenA-1]
		if int(m) < lenV-3 || int(m) > lenV { return nil }
		lenV = int(m)
	}
	res := make([]byte, lenV)
	for i := 0; i < lenV; i++ {
		res[i] = byte(a[i>>2] >> ((i & 3) * 8) & 0xff)
	}
	return res
}

// base64Srun: 保持 V3 的修复 (无Padding, 越界忽略)
func base64Srun(input []byte) string {
	alpha := srunAlphabet
	alphaLen := len(alpha)
	var sb strings.Builder
	sb.Grow((len(input) + 2) / 3 * 4)

	si := 0
	n := (len(input) / 3) * 3
	safeWrite := func(idx uint) {
		if int(idx) < alphaLen { sb.WriteByte(alpha[idx]) }
	}

	for si < n {
		val := uint(input[si+0])<<16 | uint(input[si+1])<<8 | uint(input[si+2])
		safeWrite(val >> 18 & 0x3F)
		safeWrite(val >> 12 & 0x3F)
		safeWrite(val >> 6 & 0x3F)
		safeWrite(val & 0x3F)
		si += 3
	}
	remain := len(input) - si
	if remain == 0 { return sb.String() }

	val := uint(input[si+0]) << 16
	if remain == 2 { val |= uint(input[si+1]) << 8 }

	safeWrite(val >> 18 & 0x3F)
	safeWrite(val >> 12 & 0x3F)
	if remain == 2 { safeWrite(val >> 6 & 0x3F) }
	
	return sb.String()
}
