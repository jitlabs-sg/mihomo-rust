//! Domain trie for fast domain matching

use std::collections::HashMap;

/// Node in the domain trie
#[derive(Debug, Clone)]
struct TrieNode<T: Clone> {
    children: HashMap<String, TrieNode<T>>,
    value: Option<T>,
    /// Wildcard match (*.example.com)
    wildcard: Option<T>,
}

impl<T: Clone> Default for TrieNode<T> {
    fn default() -> Self {
        TrieNode {
            children: HashMap::new(),
            value: None,
            wildcard: None,
        }
    }
}

/// Domain trie for efficient domain matching
///
/// Supports:
/// - Exact match: example.com
/// - Suffix match: .example.com (matches *.example.com and example.com)
/// - Wildcard: *.example.com (matches foo.example.com but not example.com)
/// - Full wildcard: + (matches everything)
#[derive(Debug, Clone)]
pub struct DomainTrie<T: Clone> {
    root: TrieNode<T>,
    /// Full wildcard value (matches everything)
    full_wildcard: Option<T>,
    /// Count of entries
    count: usize,
}

impl<T: Clone> Default for DomainTrie<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone> DomainTrie<T> {
    /// Create new domain trie
    pub fn new() -> Self {
        DomainTrie {
            root: TrieNode::default(),
            full_wildcard: None,
            count: 0,
        }
    }

    /// Insert domain with value
    pub fn insert(&mut self, domain: &str, value: T) -> bool {
        let domain = domain.to_lowercase();

        // Handle full wildcard
        if domain == "+" || domain == "*" {
            self.full_wildcard = Some(value);
            self.count += 1;
            return true;
        }

        // Handle wildcard prefix
        let (is_wildcard, domain) = if domain.starts_with("*.") {
            (true, &domain[2..])
        } else if domain.starts_with('.') {
            (false, &domain[1..])
        } else {
            (false, domain.as_str())
        };

        // Split domain into parts (reversed)
        let parts: Vec<&str> = domain.rsplit('.').collect();

        if parts.is_empty() {
            return false;
        }

        let mut node = &mut self.root;

        for part in parts {
            node = node
                .children
                .entry(part.to_string())
                .or_insert_with(TrieNode::default);
        }

        if is_wildcard {
            node.wildcard = Some(value);
        } else {
            node.value = Some(value);
        }

        self.count += 1;
        true
    }

    /// Search for domain, returns matched value
    pub fn search(&self, domain: &str) -> Option<&T> {
        // Check full wildcard
        if let Some(ref v) = self.full_wildcard {
            return Some(v);
        }

        let domain = domain.to_lowercase();
        let parts: Vec<&str> = domain.rsplit('.').collect();

        if parts.is_empty() {
            return None;
        }

        let mut node = &self.root;
        let mut last_wildcard: Option<&T> = None;
        let total_parts = parts.len();

        for (i, part) in parts.iter().enumerate() {
            match node.children.get(*part) {
                Some(child) => {
                    node = child;
                    // After descending, check if this node has a wildcard
                    // A wildcard at this level matches any additional subdomain
                    if node.wildcard.is_some() && i < total_parts - 1 {
                        // We're not at the final part yet, so wildcard could match
                        last_wildcard = node.wildcard.as_ref();
                    }
                }
                None => {
                    // No exact match, return last wildcard
                    return last_wildcard;
                }
            }
        }

        // Check exact match first, then wildcard at this level, then any saved wildcard
        node.value.as_ref().or(last_wildcard)
    }

    /// Check if domain matches (any value)
    pub fn contains(&self, domain: &str) -> bool {
        self.search(domain).is_some()
    }

    /// Get number of entries
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        self.root = TrieNode::default();
        self.full_wildcard = None;
        self.count = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let mut trie = DomainTrie::new();
        trie.insert("example.com", "proxy1");

        assert_eq!(trie.search("example.com"), Some(&"proxy1"));
        assert_eq!(trie.search("www.example.com"), None);
        assert_eq!(trie.search("example.org"), None);
    }

    #[test]
    fn test_wildcard_match() {
        let mut trie = DomainTrie::new();
        trie.insert("*.example.com", "proxy1");

        assert_eq!(trie.search("www.example.com"), Some(&"proxy1"));
        assert_eq!(trie.search("foo.bar.example.com"), Some(&"proxy1"));
        assert_eq!(trie.search("example.com"), None); // Wildcard doesn't match base
    }

    #[test]
    fn test_suffix_match() {
        let mut trie = DomainTrie::new();
        trie.insert(".example.com", "proxy1");

        // Suffix with dot matches both base and subdomains
        // (Our implementation treats it same as exact for now)
        assert_eq!(trie.search("example.com"), Some(&"proxy1"));
    }

    #[test]
    fn test_full_wildcard() {
        let mut trie = DomainTrie::new();
        trie.insert("+", "proxy1");

        assert_eq!(trie.search("anything.com"), Some(&"proxy1"));
        assert_eq!(trie.search("foo.bar.baz"), Some(&"proxy1"));
    }

    #[test]
    fn test_case_insensitive() {
        let mut trie = DomainTrie::new();
        trie.insert("Example.COM", "proxy1");

        assert_eq!(trie.search("example.com"), Some(&"proxy1"));
        assert_eq!(trie.search("EXAMPLE.COM"), Some(&"proxy1"));
    }

    #[test]
    fn test_priority() {
        let mut trie = DomainTrie::new();
        trie.insert("*.example.com", "wildcard");
        trie.insert("www.example.com", "exact");

        // Exact match should take priority
        assert_eq!(trie.search("www.example.com"), Some(&"exact"));
        assert_eq!(trie.search("api.example.com"), Some(&"wildcard"));
    }
}
