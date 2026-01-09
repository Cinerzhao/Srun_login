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
	return _base64(res[0:l])
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

func _base64(input []byte) string {
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
