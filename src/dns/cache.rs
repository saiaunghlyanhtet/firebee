use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// A single cached DNS resolution with its expiry time.
#[derive(Debug, Clone)]
struct CacheEntry {
    ip: IpAddr,
    expires_at: Instant,
}

/// Cache mapping domain names to their resolved IP addresses.
/// Each IP has an independent TTL from the DNS response.
pub struct DnsCache {
    entries: HashMap<String, Vec<CacheEntry>>,
    min_ttl: Duration,
}

impl DnsCache {
    pub fn new(min_ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            min_ttl,
        }
    }

    pub fn insert(&mut self, domain: &str, ip: IpAddr, ttl: Duration) -> bool {
        let effective_ttl = ttl.max(self.min_ttl);
        let expires_at = Instant::now() + effective_ttl;
        let domain = domain.to_lowercase();

        let entries = self.entries.entry(domain).or_default();

        for entry in entries.iter_mut() {
            if entry.ip == ip {
                entry.expires_at = expires_at;
                return false;
            }
        }

        entries.push(CacheEntry { ip, expires_at });
        true
    }

    #[allow(dead_code)]
    pub fn get(&self, domain: &str) -> Vec<IpAddr> {
        let domain = domain.to_lowercase();
        let now = Instant::now();

        self.entries
            .get(&domain)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| e.expires_at > now)
                    .map(|e| e.ip)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Remove expired entries from all domains.
    /// Returns the list of (domain, ip) pairs that were expired.
    pub fn sweep_expired(&mut self) -> Vec<(String, IpAddr)> {
        let now = Instant::now();
        let mut expired = Vec::new();

        self.entries.retain(|domain, entries| {
            entries.retain(|e| {
                if e.expires_at <= now {
                    expired.push((domain.clone(), e.ip));
                    false
                } else {
                    true
                }
            });
            !entries.is_empty()
        });

        expired
    }

    /// Check if a domain has any active (non-expired) entries.
    #[allow(dead_code)]
    pub fn has_entries(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();
        let now = Instant::now();
        self.entries
            .get(&domain)
            .map(|entries| entries.iter().any(|e| e.expires_at > now))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_insert_and_get() {
        let mut cache = DnsCache::new(Duration::from_secs(1));
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        assert!(cache.insert("example.com", ip, Duration::from_secs(300)));
        assert_eq!(cache.get("example.com"), vec![ip]);
    }

    #[test]
    fn test_duplicate_insert_returns_false() {
        let mut cache = DnsCache::new(Duration::from_secs(1));
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        assert!(cache.insert("example.com", ip, Duration::from_secs(300)));
        assert!(!cache.insert("example.com", ip, Duration::from_secs(300)));
    }

    #[test]
    fn test_multiple_ips_per_domain() {
        let mut cache = DnsCache::new(Duration::from_secs(1));
        let ip1 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let ip2 = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

        cache.insert("example.com", ip1, Duration::from_secs(300));
        cache.insert("example.com", ip2, Duration::from_secs(300));

        let ips = cache.get("example.com");
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&ip1));
        assert!(ips.contains(&ip2));
    }

    #[test]
    fn test_case_insensitive() {
        let mut cache = DnsCache::new(Duration::from_secs(1));
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        cache.insert("Example.COM", ip, Duration::from_secs(300));
        assert_eq!(cache.get("example.com"), vec![ip]);
    }

    #[test]
    fn test_sweep_expired() {
        let mut cache = DnsCache::new(Duration::from_millis(1));
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        // Insert with very short TTL
        cache.insert("example.com", ip, Duration::from_millis(1));

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(10));

        let expired = cache.sweep_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0, "example.com");
        assert_eq!(expired[0].1, ip);
        assert!(cache.get("example.com").is_empty());
    }

    #[test]
    fn test_min_ttl_floor() {
        let mut cache = DnsCache::new(Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        // Insert with TTL below min_ttl
        cache.insert("example.com", ip, Duration::from_secs(1));

        // Should still be valid because min_ttl is 60s
        assert!(cache.has_entries("example.com"));
    }
}
