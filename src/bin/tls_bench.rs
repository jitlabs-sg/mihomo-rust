//! TLS Handshake Latency Benchmark
//!
//! 测量 rustls 单次 TLS 握手延迟分布，定位性能根因。
//!
//! Usage: cargo run --release --bin tls_bench -- <host> <port> [count]

use std::env;
use std::io::{self, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;

fn build_tls_config() -> Arc<rustls::ClientConfig> {
    // Install aws-lc-rs as the default crypto provider
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Arc::new(config)
}

fn measure_handshake(
    host: &str,
    port: u16,
    config: Arc<rustls::ClientConfig>,
) -> io::Result<(Duration, Duration)> {
    let server_name: ServerName<'static> = host.to_string().try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid server name"))?;

    // 1. TCP 连接
    let tcp_start = Instant::now();
    let mut tcp_stream = TcpStream::connect((host, port))?;
    tcp_stream.set_nodelay(true)?;
    let tcp_duration = tcp_start.elapsed();

    // 2. TLS 握手
    let tls_start = Instant::now();
    let mut conn = rustls::ClientConnection::new(config, server_name)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    // 完成握手
    loop {
        if conn.is_handshaking() {
            conn.complete_io(&mut tcp_stream)?;
        } else {
            break;
        }
    }
    let tls_duration = tls_start.elapsed();

    Ok((tcp_duration, tls_duration))
}

fn calculate_stats(durations: &[f64]) -> (f64, f64, f64, f64, f64, f64, f64) {
    let mut sorted = durations.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let n = sorted.len();
    let sum: f64 = sorted.iter().sum();
    let mean = sum / n as f64;

    let min = sorted[0];
    let max = sorted[n - 1];
    let p50 = sorted[n * 50 / 100];
    let p90 = sorted[n * 90 / 100];
    let p99 = sorted.get(n * 99 / 100).copied().unwrap_or(sorted[n - 1]);

    let variance: f64 = sorted.iter()
        .map(|x| (x - mean).powi(2))
        .sum::<f64>() / n as f64;
    let stdev = variance.sqrt();

    (min, max, p50, p90, p99, stdev, mean)
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} <host> <port> [count]", args[0]);
        eprintln!("Example: {} example.com 443 100", args[0]);
        std::process::exit(1);
    }

    let host = &args[1];
    let port: u16 = args[2].parse().expect("Invalid port");
    let count: usize = args.get(3).map(|s| s.parse().unwrap_or(100)).unwrap_or(100);

    println!("=== TLS Handshake Latency Benchmark ===");
    println!("Host: {}:{}", host, port);
    println!("Count: {}", count);
    println!("TLS Library: rustls 0.23 + aws-lc-rs");
    println!();

    let config = build_tls_config();
    let mut tcp_durations = Vec::with_capacity(count);
    let mut tls_durations = Vec::with_capacity(count);
    let mut errors = 0;

    // 预热
    println!("Warmup (3 connections)...");
    for i in 0..3 {
        match measure_handshake(host, port, config.clone()) {
            Ok((tcp, tls)) => {
                println!("  Warmup {}: TCP={:.2}ms, TLS={:.2}ms",
                    i + 1,
                    tcp.as_secs_f64() * 1000.0,
                    tls.as_secs_f64() * 1000.0);
            }
            Err(e) => println!("  Warmup {} failed: {}", i + 1, e),
        }
    }
    println!();

    // 正式测试
    println!("Running {} handshakes...", count);
    let test_start = Instant::now();

    for i in 0..count {
        if (i + 1) % 10 == 0 || i == 0 {
            print!("\r[{}/{}] ", i + 1, count);
            io::stdout().flush()?;
        }

        match measure_handshake(host, port, config.clone()) {
            Ok((tcp, tls)) => {
                tcp_durations.push(tcp.as_secs_f64() * 1000.0);
                tls_durations.push(tls.as_secs_f64() * 1000.0);
            }
            Err(e) => {
                eprintln!("\n  Error at {}: {}", i + 1, e);
                errors += 1;
            }
        }

        // 避免被服务器限流，间隔 50ms
        std::thread::sleep(Duration::from_millis(50));
    }

    let total_time = test_start.elapsed();
    println!("\rCompleted in {:.1}s", total_time.as_secs_f64());
    println!();

    if tls_durations.is_empty() {
        eprintln!("No successful handshakes!");
        return Ok(());
    }

    // 统计 TCP
    let (tcp_min, tcp_max, tcp_p50, tcp_p90, tcp_p99, tcp_stdev, tcp_mean) =
        calculate_stats(&tcp_durations);

    // 统计 TLS
    let (tls_min, tls_max, tls_p50, tls_p90, tls_p99, tls_stdev, tls_mean) =
        calculate_stats(&tls_durations);

    // 总延迟
    let total_durations: Vec<f64> = tcp_durations.iter()
        .zip(tls_durations.iter())
        .map(|(t, s)| t + s)
        .collect();
    let (total_min, total_max, total_p50, total_p90, total_p99, total_stdev, total_mean) =
        calculate_stats(&total_durations);

    println!("=== Results ===");
    println!("Successful: {}/{}", tls_durations.len(), count);
    println!("Errors: {}", errors);
    println!();

    println!("TCP Connection Latency:");
    println!("  min:   {:>8.2}ms", tcp_min);
    println!("  p50:   {:>8.2}ms", tcp_p50);
    println!("  p90:   {:>8.2}ms", tcp_p90);
    println!("  p99:   {:>8.2}ms", tcp_p99);
    println!("  max:   {:>8.2}ms", tcp_max);
    println!("  mean:  {:>8.2}ms", tcp_mean);
    println!("  stdev: {:>8.2}ms", tcp_stdev);
    println!();

    println!("TLS Handshake Latency (rustls 0.23 + aws-lc-rs):");
    println!("  min:   {:>8.2}ms", tls_min);
    println!("  p50:   {:>8.2}ms", tls_p50);
    println!("  p90:   {:>8.2}ms", tls_p90);
    println!("  p99:   {:>8.2}ms", tls_p99);
    println!("  max:   {:>8.2}ms", tls_max);
    println!("  mean:  {:>8.2}ms", tls_mean);
    println!("  stdev: {:>8.2}ms", tls_stdev);
    println!("  p90→p99 gap: {:>6.2}ms", tls_p99 - tls_p90);
    println!();

    println!("Total (TCP + TLS):");
    println!("  min:   {:>8.2}ms", total_min);
    println!("  p50:   {:>8.2}ms", total_p50);
    println!("  p90:   {:>8.2}ms", total_p90);
    println!("  p99:   {:>8.2}ms", total_p99);
    println!("  max:   {:>8.2}ms", total_max);
    println!("  mean:  {:>8.2}ms", total_mean);
    println!("  stdev: {:>8.2}ms", total_stdev);
    println!();

    // 分析
    println!("=== Analysis ===");

    // TLS 占比
    let tls_ratio = tls_mean / total_mean * 100.0;
    println!("TLS handshake accounts for {:.1}% of total latency", tls_ratio);

    if tls_stdev > 10.0 {
        println!("⚠️  High TLS variance (stdev={:.2}ms > 10ms) - handshake time unstable", tls_stdev);
    } else {
        println!("✅ TLS variance is acceptable (stdev={:.2}ms)", tls_stdev);
    }

    if tls_p99 - tls_p90 > 10.0 {
        println!("⚠️  Large p90→p99 gap ({:.2}ms > 10ms) - occasional slow handshakes", tls_p99 - tls_p90);
    } else {
        println!("✅ p90→p99 gap is acceptable ({:.2}ms)", tls_p99 - tls_p90);
    }

    if tls_p50 > 30.0 {
        println!("⚠️  High p50 ({:.2}ms > 30ms) - base handshake latency is high", tls_p50);
        println!("   Consider: native-tls (OpenSSL) or check network RTT");
    } else {
        println!("✅ p50 is acceptable ({:.2}ms)", tls_p50);
    }

    // 与 Go 对比建议
    println!();
    println!("=== Comparison Reference ===");
    println!("Go crypto/tls typical TLS handshake: ~15-25ms (local) or ~RTT*2 (remote)");
    println!("If rustls p50 matches Go within 10%, aws-lc-rs optimization is working.");

    Ok(())
}
