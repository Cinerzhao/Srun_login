package main

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"
)

// ================= 用户提供的 F12 原始数据 =================
// 这一步是为了复现浏览器的计算过程
const (
	DEBUG_TOKEN    = "b730f0921594d0f808476cf6e8397af57e13b766e03a556f70ef63f146af0803"
	DEBUG_IP       = "121.194.120.183"
	DEBUG_ACID     = "23"
	DEBUG_USERNAME = "120222102016"
	DEBUG_PASSWORD = "12090314" // ⚠️ 请填入你当时登录用的明文密码，否则计算结果永远对不上！
	
	// F12 里抓到的目标密文 (UrlDecode 后的结果，去掉了前面的 {SRBX1})
	// 原始值: %7BSRBX1%7DRh48MP4... -> {SRBX1}Rh48MP4...
	// 我们只对比 Rh48... 这一部分
	EXPECTED_INFO  = "Rh48MP4FFZRRng3s2Alx/xefmpFhn/Bv4kiT6q+JyQmdvlx7v9twwp/986zGLZXoLpL/9pxhFe0gA4CTJUw8lwIcReQCRW/QgUfQJn5Mbu6x8rcMaavYJTFOlZjDOY5J6tP4TC0EfUsqP0ApcXRgdS=="
)

func main() {
	fmt.Println("========== SRUN 算法调试器 ==========")

	if DEBUG_PASSWORD == "你的密码(我不知道)" {
		fmt.Println("⚠️  错误: 请在代码第 20 行填入你的真实密码，然后重新运行！")
		return
	}

	// 1. 还原 Info 内部的 JSON
	// 这是一个猜想的 JSON 格式，我们需要验证它对不对
	pwdMd5 := md5Str(DEBUG_PASSWORD)
	
	// 尝试方案 A: 你的学校是否使用标准的 JSON 顺序？
	jsonA := fmt.Sprintf(`{"username":"%s","password":"%s","ip":"%s","acid":"%s","enc_ver":"srun_bx1"}`,
		DEBUG_USERNAME, pwdMd5, DEBUG_IP, DEBUG_ACID)

	fmt.Printf("[Input] JSON String: %s\n", jsonA)
	fmt.Printf("[Input] Token:       %s\n", DEBUG_TOKEN)
	fmt.Println("---------------------------------------")

	// 2. 运行加密算法
	// 这里我们只调用加密核心
	myResult := xEncode(jsonA, DEBUG_TOKEN)

	fmt.Printf("[Output] Go计算结果: %s\n", myResult)
	fmt.Printf("[Target] F12原数据 : %s\n", EXPECTED_INFO)

	fmt.Println("---------------------------------------")
	if myResult == EXPECTED_INFO {
		fmt.Println("✅ 成功匹配！算法逻辑正确！")
		fmt.Println("👉 这意味着：如果是网络请求失败，那就是 Cookie 或 Header 的问题，而不是加密的问题。")
	} else {
		fmt.Println("❌ 匹配失败！")
		analyzeDiff(myResult, EXPECTED_INFO)
	}
}

// 简单的差异分析
func analyzeDiff(got, want string) {
	if len(got) != len(want) {
		fmt.Printf("长度不同: Got %d, Want %d\n", len(got), len(want))
	}
	// 解码 Base64 看看原始字节是否接近
	bytesGot, _ := base64.StdEncoding.DecodeString(got)
	bytesWant, _ := base64.StdEncoding.DecodeString(want)
	
	if len(bytesGot) > 0 && len(bytesWant) > 0 {
		fmt.Printf("Hex Got : %x\n", bytesGot[:min(10, len(bytesGot))])
		fmt.Printf("Hex Want: %x\n", bytesWant[:min(10, len(bytesWant))])
	}
	fmt.Println("👉 建议排查方向：1. s()函数字节对齐 2. xEncode数学优先级 3. JSON字段顺序")
}

func min(a, b int) int { if a < b { return a }; return b }

// ================== 待验证的算法区域 ==================

func md5Str(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

// xEncode 实现
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
			// 优先级修复版
			mx := ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (k[(p&3)^e] ^ z))
			v[p] += mx
			z = v[p]
		}
		y = v[0]
		mx := ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (k[(n&3)^e] ^ z))
		v[n] += mx
		z = v[n]
		q--
	}
	
	byteData := l(v, false)
	return base64.StdEncoding.EncodeToString(byteData)
}

// s 函数：字符串转 uint32 数组
// 关键点：JavaScript 在处理字符串时，是追加长度在数组末尾
func s(a string, b bool) []uint32 {
	n := len(a)
	var v []uint32
	
	// 计算需要的长度。JS 中字符是按 4 字节 packed 的
	// 如果 n=4, i=0, v[0] 填满. loop结束.
	// 如果 b=true, 需要 v[1] 来存长度.
	
	lenV := (n + 3) / 4
	if b {
		v = make([]uint32, lenV+1) // 多留一个位置给长度
		v[lenV] = uint32(n)        // 长度直接放在最后这个独立的 uint32 里
	} else {
		v = make([]uint32, lenV)
	}

	for i := 0; i < n; i++ {
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
