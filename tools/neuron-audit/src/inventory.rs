//! Neuron ID inventory loading. Accepts plain lists (one or more IDs per line, `#` comments)
//! and the bash `NEURONS=( ... )` arrays used by `recovery/2026-10-22/check-neurons.sh`.

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    /// Number of IDs as written in the source, duplicates included.
    pub original_count: usize,
    /// Unique IDs, ascending.
    pub ids: Vec<u64>,
    /// Non-empty lines that held no valid IDs (shell code etc.).
    pub ignored_lines: usize,
    pub source_sha256: String,
}

impl Inventory {
    pub fn duplicates(&self) -> usize {
        self.original_count - self.ids.len()
    }
}

pub fn parse_ids(text: &str) -> Inventory {
    let mut original_count = 0;
    let mut ignored_lines = 0;
    let mut unique = BTreeSet::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let parsed: Option<Vec<u64>> = line
            .split(|c: char| c.is_whitespace() || c == ',')
            .filter(|t| !t.is_empty())
            .map(|t| t.parse::<u64>().ok().filter(|id| *id != 0))
            .collect();
        match parsed {
            Some(ids) => {
                for id in ids {
                    original_count += 1;
                    unique.insert(id);
                }
            }
            None => ignored_lines += 1,
        }
    }
    Inventory {
        original_count,
        ids: unique.into_iter().collect(),
        ignored_lines,
        source_sha256: Sha256::digest(text.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bash_array_and_deduplicates() {
        let text = r#"
#!/usr/bin/env bash
GOVERNANCE="rrkah-fqaaa-aaaaa-aaaaq-cai"
NEURONS=(
436472328193651593
1479873936384536384
  16136654443876485299
  1479873936384536384
10700420421638256614
10700420421638256614
)
# Deduplicate neuron IDs before querying NNS.
NEURONS=($(printf '%s\n' "${NEURONS[@]}" | sort -u))
total_e8s=0
"#;
        let inv = parse_ids(text);
        assert_eq!(inv.original_count, 6);
        assert_eq!(inv.ids.len(), 4);
        assert_eq!(inv.duplicates(), 2);
        assert_eq!(inv.ignored_lines, 5);
        assert!(inv.ids.windows(2).all(|w| w[0] < w[1]));
        assert!(inv.ids.contains(&16136654443876485299)); // > i64::MAX
        assert_eq!(inv.source_sha256.len(), 64);
    }

    #[test]
    fn parses_plain_lists_with_commas_and_comments() {
        let inv = parse_ids("1, 2 3 # trailing\n\n# only a comment\n3\n0\n");
        assert_eq!(inv.ids, vec![1, 2, 3]);
        assert_eq!(inv.original_count, 4);
        assert_eq!(inv.ignored_lines, 1); // "0" is not a valid neuron ID
    }

    #[test]
    fn rejects_overflowing_and_mixed_lines() {
        let inv = parse_ids("18446744073709551616\n12 abc\n");
        assert!(inv.ids.is_empty());
        assert_eq!(inv.ignored_lines, 2);
    }

    #[test]
    fn hash_changes_with_content() {
        assert_ne!(
            parse_ids("1\n").source_sha256,
            parse_ids("2\n").source_sha256
        );
    }
}
