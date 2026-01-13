// TLS Handshake Latency Benchmark - Go Version
//
// 测量 Go crypto/tls 单次 TLS 握手延迟分布，与 Rust 版本对比。
//
// Usage: go run tls_bench_go.go <host> <port> [count]

package main

import (
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"os"
	"sort"
	"strconv"
	"time"
)

func measureHandshake(host string, port int) (tcpDuration, tlsDuration time.Duration, err error) {
	addr := fmt.Sprintf("%s:%d", host, port)

	// 1. TCP 连接
	tcpStart := time.Now()
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return 0, 0, err
	}
	tcpDuration = time.Since(tcpStart)

	// 2. TLS 握手
	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: false,
	}

	tlsStart := time.Now()
	tlsConn := tls.Client(conn, tlsConfig)
	err = tlsConn.Handshake()
	tlsDuration = time.Since(tlsStart)

	tlsConn.Close()

	if err != nil {
		return tcpDuration, 0, err
	}

	return tcpDuration, tlsDuration, nil
}

func calculateStats(durations []float64) (min, max, p50, p90, p99, stdev, mean float64) {
	sort.Float64s(durations)
	n := len(durations)

	sum := 0.0
	for _, d := range durations {
		sum += d
	}
	mean = sum / float64(n)

	min = durations[0]
	max = durations[n-1]
	p50 = durations[n*50/100]
	p90 = durations[n*90/100]
	if n*99/100 < n {
		p99 = durations[n*99/100]
	} else {
		p99 = durations[n-1]
	}

	variance := 0.0
	for _, d := range durations {
		variance += (d - mean) * (d - mean)
	}
	variance /= float64(n)
	stdev = math.Sqrt(variance)

	return
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <host> <port> [count]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s example.com 443 100\n", os.Args[0])
		os.Exit(1)
	}

	host := os.Args[1]
	port, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid port: %v\n", err)
		os.Exit(1)
	}

	count := 100
	if len(os.Args) >= 4 {
		count, _ = strconv.Atoi(os.Args[3])
	}

	fmt.Println("=== TLS Handshake Latency Benchmark ===")
	fmt.Printf("Host: %s:%d\n", host, port)
	fmt.Printf("Count: %d\n", count)
	fmt.Println("TLS Library: Go crypto/tls")
	fmt.Println()

	var tcpDurations []float64
	var tlsDurations []float64
	errors := 0

	// 预热
	fmt.Println("Warmup (3 connections)...")
	for i := 0; i < 3; i++ {
		tcp, tls, err := measureHandshake(host, port)
		if err != nil {
			fmt.Printf("  Warmup %d failed: %v\n", i+1, err)
		} else {
			fmt.Printf("  Warmup %d: TCP=%.2fms, TLS=%.2fms\n",
				i+1,
				float64(tcp.Microseconds())/1000.0,
				float64(tls.Microseconds())/1000.0)
		}
	}
	fmt.Println()

	// 正式测试
	fmt.Printf("Running %d handshakes...\n", count)
	testStart := time.Now()

	for i := 0; i < count; i++ {
		if (i+1)%10 == 0 || i == 0 {
			fmt.Printf("\r[%d/%d] ", i+1, count)
		}

		tcp, tls, err := measureHandshake(host, port)
		if err != nil {
			fmt.Printf("\n  Error at %d: %v\n", i+1, err)
			errors++
		} else {
			tcpDurations = append(tcpDurations, float64(tcp.Microseconds())/1000.0)
			tlsDurations = append(tlsDurations, float64(tls.Microseconds())/1000.0)
		}

		// 避免被服务器限流
		time.Sleep(50 * time.Millisecond)
	}

	totalTime := time.Since(testStart)
	fmt.Printf("\rCompleted in %.1fs\n", totalTime.Seconds())
	fmt.Println()

	if len(tlsDurations) == 0 {
		fmt.Fprintln(os.Stderr, "No successful handshakes!")
		return
	}

	// 统计 TCP
	tcpMin, tcpMax, tcpP50, tcpP90, tcpP99, tcpStdev, tcpMean := calculateStats(tcpDurations)

	// 统计 TLS
	tlsMin, tlsMax, tlsP50, tlsP90, tlsP99, tlsStdev, tlsMean := calculateStats(tlsDurations)

	// 总延迟
	var totalDurations []float64
	for i := range tcpDurations {
		totalDurations = append(totalDurations, tcpDurations[i]+tlsDurations[i])
	}
	totalMin, totalMax, totalP50, totalP90, totalP99, totalStdev, totalMean := calculateStats(totalDurations)

	fmt.Println("=== Results ===")
	fmt.Printf("Successful: %d/%d\n", len(tlsDurations), count)
	fmt.Printf("Errors: %d\n", errors)
	fmt.Println()

	fmt.Println("TCP Connection Latency:")
	fmt.Printf("  min:   %8.2fms\n", tcpMin)
	fmt.Printf("  p50:   %8.2fms\n", tcpP50)
	fmt.Printf("  p90:   %8.2fms\n", tcpP90)
	fmt.Printf("  p99:   %8.2fms\n", tcpP99)
	fmt.Printf("  max:   %8.2fms\n", tcpMax)
	fmt.Printf("  mean:  %8.2fms\n", tcpMean)
	fmt.Printf("  stdev: %8.2fms\n", tcpStdev)
	fmt.Println()

	fmt.Println("TLS Handshake Latency (Go crypto/tls):")
	fmt.Printf("  min:   %8.2fms\n", tlsMin)
	fmt.Printf("  p50:   %8.2fms\n", tlsP50)
	fmt.Printf("  p90:   %8.2fms\n", tlsP90)
	fmt.Printf("  p99:   %8.2fms\n", tlsP99)
	fmt.Printf("  max:   %8.2fms\n", tlsMax)
	fmt.Printf("  mean:  %8.2fms\n", tlsMean)
	fmt.Printf("  stdev: %8.2fms\n", tlsStdev)
	fmt.Printf("  p90→p99 gap: %6.2fms\n", tlsP99-tlsP90)
	fmt.Println()

	fmt.Println("Total (TCP + TLS):")
	fmt.Printf("  min:   %8.2fms\n", totalMin)
	fmt.Printf("  p50:   %8.2fms\n", totalP50)
	fmt.Printf("  p90:   %8.2fms\n", totalP90)
	fmt.Printf("  p99:   %8.2fms\n", totalP99)
	fmt.Printf("  max:   %8.2fms\n", totalMax)
	fmt.Printf("  mean:  %8.2fms\n", totalMean)
	fmt.Printf("  stdev: %8.2fms\n", totalStdev)
	fmt.Println()

	// 分析
	fmt.Println("=== Analysis ===")
	tlsRatio := tlsMean / totalMean * 100.0
	fmt.Printf("TLS handshake accounts for %.1f%% of total latency\n", tlsRatio)

	if tlsStdev > 10.0 {
		fmt.Printf("⚠️  High TLS variance (stdev=%.2fms > 10ms) - handshake time unstable\n", tlsStdev)
	} else {
		fmt.Printf("✅ TLS variance is acceptable (stdev=%.2fms)\n", tlsStdev)
	}

	if tlsP99-tlsP90 > 10.0 {
		fmt.Printf("⚠️  Large p90→p99 gap (%.2fms > 10ms) - occasional slow handshakes\n", tlsP99-tlsP90)
	} else {
		fmt.Printf("✅ p90→p99 gap is acceptable (%.2fms)\n", tlsP99-tlsP90)
	}

	if tlsP50 > 30.0 {
		fmt.Printf("⚠️  High p50 (%.2fms > 30ms) - base handshake latency is high\n", tlsP50)
	} else {
		fmt.Printf("✅ p50 is acceptable (%.2fms)\n", tlsP50)
	}
}
