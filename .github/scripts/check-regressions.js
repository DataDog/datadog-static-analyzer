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
      current.physicalLocation = i.locations[0].physicalLocation;
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
      for (const item of diff1) {
        const json = JSON.parse(item);
        table1.push([
          { data: json.physicalLocation.artifactLocation.uri },
          { data: json.message.text },
          { data: json.ruleId },
          { data: `${json.physicalLocation.region.startLine}:${json.physicalLocation.region.startColumn}-${json.physicalLocation.region.endLine}:${json.physicalLocation.region.endColumn}` },
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
          { data: `${json.physicalLocation.region.startLine}:${json.physicalLocation.region.startColumn}-${json.physicalLocation.region.endLine}:${json.physicalLocation.region.endColumn}` },
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
