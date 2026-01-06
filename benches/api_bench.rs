//! API Benchmark tests
//!
//! Run with: cargo bench

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

fn bench_rule_matching(c: &mut Criterion) {
    use mihomo_rust::common::Metadata;
    use mihomo_rust::rule::RuleEngine;

    // Create rule engine with common rules
    let rules = vec![
        "DOMAIN-SUFFIX,google.com,PROXY".to_string(),
        "DOMAIN-SUFFIX,facebook.com,PROXY".to_string(),
        "DOMAIN-SUFFIX,twitter.com,PROXY".to_string(),
        "DOMAIN-SUFFIX,youtube.com,PROXY".to_string(),
        "DOMAIN,example.org,DIRECT".to_string(),
        "DOMAIN-KEYWORD,cdn,PROXY".to_string(),
        "IP-CIDR,192.168.0.0/16,DIRECT".to_string(),
        "IP-CIDR,10.0.0.0/8,DIRECT".to_string(),
        "MATCH,DIRECT".to_string(),
    ];

    let engine = RuleEngine::new(&rules).unwrap();

    let mut group = c.benchmark_group("rule_matching");
    group.throughput(Throughput::Elements(1));

    // Benchmark domain suffix match
    group.bench_function("domain_suffix_match", |b| {
        let metadata = Metadata::tcp()
            .with_host("www.google.com".to_string())
            .with_dst_port(443);
        b.iter(|| black_box(engine.match_rules(&metadata)))
    });

    // Benchmark domain keyword match
    group.bench_function("domain_keyword_match", |b| {
        let metadata = Metadata::tcp()
            .with_host("static.cdn.example.com".to_string())
            .with_dst_port(443);
        b.iter(|| black_box(engine.match_rules(&metadata)))
    });

    // Benchmark no match (falls through to MATCH)
    group.bench_function("fallback_match", |b| {
        let metadata = Metadata::tcp()
            .with_host("unknown.example.net".to_string())
            .with_dst_port(80);
        b.iter(|| black_box(engine.match_rules(&metadata)))
    });

    group.finish();
}

fn bench_dns_cache(c: &mut Criterion) {
    use mihomo_rust::dns::DnsCache;
    use std::net::{IpAddr, Ipv4Addr};

    let cache = DnsCache::new(10000);

    // Pre-populate cache
    for i in 0..1000 {
        let domain = format!("example{}.com", i);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, (i / 256) as u8, (i % 256) as u8));
        cache.put(domain, vec![ip]);
    }

    let mut group = c.benchmark_group("dns_cache");
    group.throughput(Throughput::Elements(1));

    group.bench_function("cache_hit", |b| {
        b.iter(|| black_box(cache.get("example500.com")))
    });

    group.bench_function("cache_miss", |b| {
        b.iter(|| black_box(cache.get("nonexistent.com")))
    });

    group.bench_function("cache_put", |b| {
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        b.iter(|| cache.put(black_box("newdomain.com".to_string()), vec![ip]))
    });

    group.finish();
}

fn bench_domain_trie(c: &mut Criterion) {
    use mihomo_rust::rule::DomainTrie;

    let mut trie: DomainTrie<String> = DomainTrie::new();

    // Insert common TLDs and domains
    let domains = [
        "*.google.com",
        "*.facebook.com",
        "*.twitter.com",
        "*.youtube.com",
        "*.github.com",
        "*.amazonaws.com",
        "*.cloudflare.com",
    ];

    for domain in &domains {
        trie.insert(domain, "PROXY".to_string());
    }

    let mut group = c.benchmark_group("domain_trie");
    group.throughput(Throughput::Elements(1));

    group.bench_function("trie_search_hit", |b| {
        b.iter(|| black_box(trie.search("api.github.com")))
    });

    group.bench_function("trie_search_miss", |b| {
        b.iter(|| black_box(trie.search("unknown.example.org")))
    });

    group.finish();
}

criterion_group!(benches, bench_rule_matching, bench_dns_cache, bench_domain_trie);
criterion_main!(benches);
