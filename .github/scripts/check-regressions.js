import { dedup, difference } from './dedup.js';
import { readFileSync } from 'node:fs';
import * as action from '@actions/core';

/**
 * Parses the JSON file at the given path and maps the results to a more readable format.
 * If another field is needed in the future for reports, we can add it to the object.
 *
 * @param {string} filepath
 *
 * @returns {object[]}
 */
const parseFile = (filepath) => {
  try {
    const data = readFileSync(filepath, 'utf8');
    const json = JSON.parse(data);

    const res = json.runs[0].results;
    const results = [];

    for (const i of res) {
      const current = {};
      current.message = i.message;
      current.ruleId = i.ruleId;
      // ------------------------------------------------------------------
      // IMPORTANT (TEMPORARY): strip `startColumn` / `endColumn` from the region.
      //
      // PR #914 changes the kernel from emitting 1-based UTF-8 byte columns to
      // 1-based UTF-16 code-unit columns (matching LSP / VS Code / SARIF v2.1).
      //
      // While that PR is in review, `main` still emits byte columns and the
      // feature branch emits UTF-16 columns. The regression check compares
      // results as JSON strings, so it would flag every violation that lives
      // on a line containing a non-ASCII character as a "removed + added"
      // pair — same file, same rule, same line; only the column number drifts
      // by N (where N is the number of multibyte chars before the position).
      //
      // To unblock CI for #914 we compare by
      //     (file, ruleId, message, startLine, endLine)
      // and intentionally ignore columns. This is a one-shot loosening for
      // the byte→UTF-16 transition. A stacked follow-up PR will restore
      // `startColumn` / `endColumn` to the comparison key once #914 lands on
      // `main` (at which point both runs are on UTF-16 columns again and
      // column-level regression detection becomes meaningful again).
      // ------------------------------------------------------------------
      const { startColumn: _startCol, endColumn: _endCol, ...regionWithoutColumns } =
        i.locations[0].physicalLocation.region;
      current.physicalLocation = {
        ...i.locations[0].physicalLocation,
        region: regionWithoutColumns,
      };
      results.push(current);
    }

    return results;
  } catch (e) {
    console.error(`Error: couldn't parse ${filepath} (${e})`);
    action.setFailed(`Error: couldn't parse ${filepath} (${e})`);
    process.exit(1);
  }
};

const main = async () => {
  try {
    const repo = process.argv[2];
    const file1 = process.argv[3];
    const file2 = process.argv[4];

    const parsed1 = parseFile(file1);
    const parsed2 = parseFile(file2);

    const set1 = new Set(parsed1.map(JSON.stringify));
    const set2 = new Set(parsed2.map(JSON.stringify));

    const [diff1, dupes1] = dedup(difference(set1, set2));
    const [diff2, dupes2] = dedup(difference(set2, set1));

    const count1 = diff1.size;
    const count2 = diff2.size;

    let table1 = [];

    if (count1 > 0 || count2 > 0) {
      // Location display only shows `startLine-endLine`. Columns are
      // intentionally omitted to match the comparison key (see `parseFile`
      // above for the full rationale on the byte→UTF-16 transition).
      for (const item of diff1) {
        const json = JSON.parse(item);
        table1.push([
          { data: json.physicalLocation.artifactLocation.uri },
          { data: json.message.text },
          { data: json.ruleId },
          { data: `${json.physicalLocation.region.startLine}-${json.physicalLocation.region.endLine}` },
          { data: dupes1[json.ruleId] },
        ]);
      }

      let table2 = [];

      for (const item of diff2) {
        const json = JSON.parse(item);
        table2.push([
          { data: json.physicalLocation.artifactLocation.uri },
          { data: json.message.text },
          { data: json.ruleId },
          { data: `${json.physicalLocation.region.startLine}-${json.physicalLocation.region.endLine}` },
          { data: dupes2[json.ruleId] },
        ]);
      }

      const headerTable = [
        { data: 'File', header: true },
        { data: 'Message', header: true },
        { data: 'Rule', header: true },
        { data: 'Location', header: true },
        { data: 'Total Occurrences', header: true },
      ];

      action.summary.addHeading(`Possible regressions detected in ${repo}`, 1);

      action.summary
        .addHeading(`${count1} ${count1 === 1 ? 'result' : 'results'} that ${count1 === 1 ? 'is' : 'are'} no longer being detected`, 2)
        .addTable([
          headerTable,
          ...table1,
        ]);

      action.summary
        .addHeading(`${count2} ${count2 === 1 ? 'result' : 'results'} that ${count2 === 1 ? 'is' : 'are'} now being detected`, 2)
        .addTable([
          headerTable,
          ...table2,
        ]);

      const getUniqueFiles = (diff) => {
        return [...new Set([...diff].map(JSON.parse).map((x) => `${repo}/${x.physicalLocation.artifactLocation.uri}`))];
      };

      if (count1 > 0) {
        action.setOutput('diff1files', getUniqueFiles(diff1).join('\n'));
      }
      if (count2 > 0) {
        action.setOutput('diff2files', getUniqueFiles(diff2).join('\n'));
      }

      await action.summary.write();
    }
  } catch (error) {
    console.error(`Failed to compute diff: ${error}`);
    action.setFailed(error.message);
    process.exit(1);
  }
}

await main();
