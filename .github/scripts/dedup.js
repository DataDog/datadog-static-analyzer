/**
 * Removes duplicate results from the given set of diffs.
 * The strategy is to keep the first occurrence of a ruleId and remove the rest.
 *
 * @param {Set<object>} diffs
 *
 * @returns {object} An object containing the deduplicated set of diffs and a map of ruleIds to their count.
 */
export const dedup = (diffs) => {
  const seen = {};
  const remove = [];
  for (const diff of diffs) {
    const json = JSON.parse(diff);
    if (seen[json.ruleId]) {
      remove.push(diff)
    }
    seen[json.ruleId] = (seen[json.ruleId] || 0) + 1;
  }
  for (const diff of remove) {
    diffs.delete(diff);
  }

  return [diffs, seen];
};

/**
 * Creates a set from the difference between two sets.
 *
 * @param {Set<object>} set1
 *
 * @param {Set<object>} set2
 *
 * @returns {Set<object>}
 */
export const difference = (set1, set2) => {
  return new Set([...set1].filter(x => !set2.has(x)));
}
