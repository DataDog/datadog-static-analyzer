use std::collections::HashMap;

/// A trie that stores values based on a pathname, splitting it by the '/'.
pub struct PathTrie<V> {
    value: Option<V>,
    children: HashMap<String, PathTrie<V>>,
}

impl<V> PathTrie<V> {
    pub fn new() -> PathTrie<V> {
        PathTrie {
            value: None,
            children: HashMap::new(),
        }
    }

    /// Inserts a value for the given path.
    pub fn insert(&mut self, path: &str, value: V) {
        let mut node = self;
        for part in path.split('/').filter(|c| !c.is_empty()) {
            node = node
                .children
                .entry(part.to_string())
                .or_default();
        }
        node.value = Some(value)
    }

    /// Returns an iterator that yields all the values for prefixes of the given path.
    /// The iterator returns (usize, V) tuples, where the first element is the prefix length.
    pub fn find_by_prefix<'k>(&self, path: &'k str) -> MatchingPrefix<'_, 'k, V> {
        MatchingPrefix {
            path: path.split('/').filter(|c| !c.is_empty()).collect(),
            level: 0,
            node: self,
        }
    }
}

impl<V> Default for PathTrie<V> {
    fn default() -> Self {
        PathTrie::new()
    }
}

/// Iterator that yields values associated with prefixes of a path.
pub struct MatchingPrefix<'t, 'k, V> {
    path: Vec<&'k str>,
    level: usize,
    node: &'t PathTrie<V>,
}

impl<'t, 'k, V> Iterator for MatchingPrefix<'t, 'k, V> {
    type Item = (usize, &'t V);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.level > self.path.len() {
                return None;
            }
            let out = self.node.value.as_ref().map(|value| (self.level, value));
            if self.level < self.path.len() {
                if let Some(child) = self.node.children.get(self.path[self.level]) {
                    self.node = child;
                } else {
                    self.level = self.path.len()
                }
            }
            self.level += 1;
            if out.is_some() {
                return out;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_trie() {
        let trie: PathTrie<bool> = PathTrie::new();
        assert_eq!(trie.find_by_prefix("a/b/c").count(), 0);
    }

    #[test]
    fn element_in_root() {
        let mut trie = PathTrie::new();
        trie.insert("", 42);
        let collected: Vec<(usize, i32)> = trie
            .find_by_prefix("anything/at/all")
            .map(|(l, v)| (l, *v))
            .collect();
        assert_eq!(collected, vec![(0, 42)]);
    }

    #[test]
    fn element_one_level_down() {
        let mut trie = PathTrie::new();
        trie.insert("anything", 42);
        let collected: Vec<(usize, i32)> = trie
            .find_by_prefix("anything/at/all")
            .map(|(l, v)| (l, *v))
            .collect();
        assert_eq!(collected, vec![(1, 42)]);
    }

    #[test]
    fn element_not_found() {
        let mut trie = PathTrie::new();
        trie.insert("nothing", 42);
        let collected: Vec<(usize, i32)> = trie
            .find_by_prefix("anything/at/all")
            .map(|(l, v)| (l, *v))
            .collect();
        assert_eq!(collected, vec![]);
    }

    #[test]
    fn elements_at_several_levels() {
        let mut trie = PathTrie::new();
        trie.insert("anything", 42);
        trie.insert("anything/at/all", 64);
        trie.insert("anything/at/all/you/may/wish", 184);
        let collected: Vec<(usize, i32)> = trie
            .find_by_prefix("anything/at/all")
            .map(|(l, v)| (l, *v))
            .collect();
        assert_eq!(collected, vec![(1, 42), (3, 64)]);
    }

    #[test]
    fn more_complex_tree() {
        let mut trie = PathTrie::new();
        trie.insert("anything", 42);
        trie.insert("anything/at", 64);
        trie.insert("anything/but", 83);
        trie.insert("anything/at/something", 184);
        trie.insert("something/at", 249);
        let collected: Vec<(usize, i32)> = trie
            .find_by_prefix("anything/at/all")
            .map(|(l, v)| (l, *v))
            .collect();
        assert_eq!(collected, vec![(1, 42), (2, 64)]);
    }
}
