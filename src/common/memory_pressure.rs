//! `memory_pressure_q10` 信号的来源与映射（整数 Q10：0..=1024）。
//!
//! 设计目标：
//! - 不把 I/O 放进热路径：建议后台定期采样（如 200ms~1s），写入 `AtomicU16`
//! - 信号更"像策略"而不是精确计量：配合阈值 + 线性映射，避免抖动
//!
//! 常用用法：
//! - 系统压力（Linux）：`/proc/meminfo` 的 `MemAvailable/MemTotal`
//! - 容器/进程预算：cgroup v2 `memory.current/memory.max`，或 jemalloc `stats.resident` vs budget
//!
//! # Example
//! ```ignore
//! use std::sync::atomic::{AtomicU16, Ordering};
//! use std::sync::Arc;
//!
//! let pressure = Arc::new(AtomicU16::new(0));
//! let p = pressure.clone();
//!
//! // Background sampler (spawn once)
//! tokio::spawn(async move {
//!     loop {
//!         if let Ok(v) = system_pressure_from_proc_meminfo_q10() {
//!             p.store(v, Ordering::Relaxed);
//!         }
//!         tokio::time::sleep(Duration::from_millis(500)).await;
//!     }
//! });
//!
//! // Hot path: just load
//! let current_pressure = pressure.load(Ordering::Relaxed);
//! ```

#[cfg(target_os = "linux")]
use std::io;

/// Q10 representation of 1.0 (100%)
pub const Q10_ONE: u16 = 1024;

/// Default threshold: avail >= 40% => pressure = 0
pub const DEFAULT_AVAIL_HI_Q10: u16 = pct_to_q10(40);
/// Default threshold: avail <= 10% => pressure = 1.0
pub const DEFAULT_AVAIL_LO_Q10: u16 = pct_to_q10(10);

/// Default threshold: usage <= 70% => pressure = 0
pub const DEFAULT_USAGE_LO_Q10: u16 = pct_to_q10(70);
/// Default threshold: usage >= 90% => pressure = 1.0
pub const DEFAULT_USAGE_HI_Q10: u16 = pct_to_q10(90);

/// Convert percentage (0-100) to Q10 representation (0-1024).
pub const fn pct_to_q10(pct: u16) -> u16 {
    // (pct/100)*1024，四舍五入
    // Note: do division in u32 to avoid truncation before division
    (((pct as u32 * Q10_ONE as u32) + 50) / 100) as u16
}

/// Calculate `num/denom` as Q10 ratio (0..=1024), clamped.
pub fn ratio_q10(num: u64, denom: u64) -> u16 {
    if denom == 0 {
        return Q10_ONE;
    }
    let v = (num.saturating_mul(Q10_ONE as u64) / denom) as u64;
    if v >= Q10_ONE as u64 {
        Q10_ONE
    } else {
        v as u16
    }
}

/// Calculate pressure from available memory ratio: lower avail = higher pressure.
///
/// - `avail_q10 >= avail_hi_q10` => 0
/// - `avail_q10 <= avail_lo_q10` => 1024
/// - Linear interpolation in between
pub fn pressure_from_available_q10(avail_q10: u16, avail_hi_q10: u16, avail_lo_q10: u16) -> u16 {
    if avail_hi_q10 <= avail_lo_q10 {
        return if avail_q10 >= avail_hi_q10 { 0 } else { Q10_ONE };
    }
    if avail_q10 >= avail_hi_q10 {
        return 0;
    }
    if avail_q10 <= avail_lo_q10 {
        return Q10_ONE;
    }
    let num = (avail_hi_q10 - avail_q10) as u32 * Q10_ONE as u32;
    let den = (avail_hi_q10 - avail_lo_q10) as u32;
    (num / den).min(Q10_ONE as u32) as u16
}

/// Calculate pressure from usage ratio: higher usage = higher pressure.
///
/// - `usage_q10 <= usage_lo_q10` => 0
/// - `usage_q10 >= usage_hi_q10` => 1024
/// - Linear interpolation in between
pub fn pressure_from_usage_q10(usage_q10: u16, usage_lo_q10: u16, usage_hi_q10: u16) -> u16 {
    if usage_hi_q10 <= usage_lo_q10 {
        return if usage_q10 >= usage_hi_q10 { Q10_ONE } else { 0 };
    }
    if usage_q10 <= usage_lo_q10 {
        return 0;
    }
    if usage_q10 >= usage_hi_q10 {
        return Q10_ONE;
    }
    let num = (usage_q10 - usage_lo_q10) as u32 * Q10_ONE as u32;
    let den = (usage_hi_q10 - usage_lo_q10) as u32;
    (num / den).min(Q10_ONE as u32) as u16
}

/// Read system memory pressure from `/proc/meminfo` (Linux only).
///
/// Returns Q10 pressure value (0 = no pressure, 1024 = max pressure).
#[cfg(target_os = "linux")]
pub fn system_pressure_from_proc_meminfo_q10() -> io::Result<u16> {
    let (total_kb, avail_kb) = read_proc_meminfo_total_avail_kb()?;
    let avail_q10 = ratio_q10(avail_kb, total_kb);
    Ok(pressure_from_available_q10(
        avail_q10,
        DEFAULT_AVAIL_HI_Q10,
        DEFAULT_AVAIL_LO_Q10,
    ))
}

/// Read MemTotal and MemAvailable from `/proc/meminfo`.
#[cfg(target_os = "linux")]
pub fn read_proc_meminfo_total_avail_kb() -> io::Result<(u64, u64)> {
    let contents = std::fs::read_to_string("/proc/meminfo")?;
    parse_meminfo_total_avail_kb(&contents)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing MemTotal/MemAvailable"))
}

#[cfg(target_os = "linux")]
fn parse_meminfo_total_avail_kb(contents: &str) -> Option<(u64, u64)> {
    let mut total: Option<u64> = None;
    let mut avail: Option<u64> = None;
    for line in contents.lines() {
        if total.is_none() && line.starts_with("MemTotal:") {
            total = parse_meminfo_kb_value(line);
        } else if avail.is_none() && line.starts_with("MemAvailable:") {
            avail = parse_meminfo_kb_value(line);
        }
        if total.is_some() && avail.is_some() {
            break;
        }
    }
    Some((total?, avail?))
}

#[cfg(target_os = "linux")]
fn parse_meminfo_kb_value(line: &str) -> Option<u64> {
    // e.g. "MemAvailable:   123456 kB"
    line.split_whitespace().nth(1)?.parse::<u64>().ok()
}

/// Read cgroup v2 memory pressure (Linux only).
///
/// Returns `Ok(Some(pressure))` if cgroup limits are set, `Ok(None)` if unlimited ("max").
#[cfg(target_os = "linux")]
pub fn cgroup2_pressure_q10() -> io::Result<Option<u16>> {
    let limit_raw = std::fs::read_to_string("/sys/fs/cgroup/memory.max");
    let usage_raw = std::fs::read_to_string("/sys/fs/cgroup/memory.current");
    let (limit_raw, usage_raw) = match (limit_raw, usage_raw) {
        (Ok(l), Ok(u)) => (l, u),
        _ => return Ok(None),
    };

    let limit_s = limit_raw.trim();
    if limit_s == "max" {
        return Ok(None);
    }
    let limit = limit_s
        .parse::<u64>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid cgroup memory.max"))?;
    if limit == 0 {
        return Ok(None);
    }
    let usage = usage_raw
        .trim()
        .parse::<u64>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid cgroup memory.current"))?;

    let usage_q10 = ratio_q10(usage, limit);
    Ok(Some(pressure_from_usage_q10(
        usage_q10,
        DEFAULT_USAGE_LO_Q10,
        DEFAULT_USAGE_HI_Q10,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn available_mapping_has_expected_extremes() {
        assert_eq!(
            pressure_from_available_q10(DEFAULT_AVAIL_HI_Q10, DEFAULT_AVAIL_HI_Q10, DEFAULT_AVAIL_LO_Q10),
            0
        );
        assert_eq!(
            pressure_from_available_q10(DEFAULT_AVAIL_LO_Q10, DEFAULT_AVAIL_HI_Q10, DEFAULT_AVAIL_LO_Q10),
            Q10_ONE
        );
    }

    #[test]
    fn usage_mapping_has_expected_extremes() {
        assert_eq!(
            pressure_from_usage_q10(DEFAULT_USAGE_LO_Q10, DEFAULT_USAGE_LO_Q10, DEFAULT_USAGE_HI_Q10),
            0
        );
        assert_eq!(
            pressure_from_usage_q10(DEFAULT_USAGE_HI_Q10, DEFAULT_USAGE_LO_Q10, DEFAULT_USAGE_HI_Q10),
            Q10_ONE
        );
    }

    #[test]
    fn ratio_q10_clamps() {
        assert_eq!(ratio_q10(10, 0), Q10_ONE);
        assert_eq!(ratio_q10(10, 10), Q10_ONE);
        assert_eq!(ratio_q10(0, 10), 0);
    }

    #[test]
    fn pct_to_q10_conversions() {
        assert_eq!(pct_to_q10(0), 0);
        assert_eq!(pct_to_q10(50), 512);
        assert_eq!(pct_to_q10(100), 1024);
    }

    #[test]
    fn pressure_linear_interpolation() {
        // 25% available should give ~50% pressure (between 40% and 10%)
        let avail_25_q10 = pct_to_q10(25);
        let pressure = pressure_from_available_q10(avail_25_q10, DEFAULT_AVAIL_HI_Q10, DEFAULT_AVAIL_LO_Q10);
        // Expected: (40-25)/(40-10) = 15/30 = 0.5 => 512
        assert!(pressure > 450 && pressure < 550, "pressure = {}", pressure);
    }
}
