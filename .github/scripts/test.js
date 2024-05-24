import { dedup, difference } from './dedup.js';
import { describe, it } from 'node:test';
import * as assert from 'node:assert';

describe('dedup', () => {
  it('should remove duplicates within its own set', () => {
    const set = new Set([
      JSON.stringify({
        physicalLocation: {
          artifactLocation: {
            uri: 'file1',
          },
          region: {
            startLine: 1,
            startColumn: 1,
            endLine: 1,
            endColumn: 1,
          },
        },
        message: {
          text: 'message1',
        },
        ruleId: 'rule1',
      }),
      JSON.stringify({
        physicalLocation: {
          artifactLocation: {
            uri: 'file2',
          },
          region: {
            startLine: 3,
            startColumn: 3,
            endLine: 3,
            endColumn: 3,
          },
        },
        message: {
          text: 'message1',
        },
        ruleId: 'rule1', // duplicate rule *within* this set here
      }),
    ]);
    const [diff] = dedup(set);
    assert.strictEqual(diff.size, 1);
  });

  it('should remove duplicates from the other set', () => {
    const set1 = new Set([
      JSON.stringify({
        physicalLocation: {
          artifactLocation: {
            uri: 'file1',
          },
          region: {
            startLine: 1,
            startColumn: 1,
            endLine: 1,
            endColumn: 1,
          },
        },
        message: {
          text: 'message1',
        },
        ruleId: 'rule1',
      }),
      JSON.stringify({
        physicalLocation: {
          artifactLocation: {
            uri: 'file2',
          },
          region: {
            startLine: 2,
            startColumn: 2,
            endLine: 2,
            endColumn: 2,
          },
        },
        message: {
          text: 'message2',
        },
        ruleId: 'rule2', // duplicated rule is in the other set
      }),
    ]);

    const set2 = new Set([
      JSON.stringify({
        physicalLocation: {
          artifactLocation: {
            uri: 'file3',
          },
          region: {
            startLine: 1,
            startColumn: 1,
            endLine: 1,
            endColumn: 1,
          },
        },
        message: {
          text: 'message1',
        },
        ruleId: 'rule1',
      }),
      JSON.stringify({
        physicalLocation: {
          artifactLocation: {
            uri: 'file2',
          },
          region: {
            startLine: 2,
            startColumn: 2,
            endLine: 2,
            endColumn: 2,
          },
        },
        message: {
          text: 'message2',
        },
        ruleId: 'rule2', // duplicate rule *from* the other set here
      }),
    ]);

    const [diff] = dedup(difference(set1, set2));
    assert.strictEqual(diff.size, 1);
  });

  it('should remove duplicates within its own set and from the other set', () => {
    const set1 = new Set([
      JSON.stringify({
        physicalLocation: {
          artifactLocation: {
            uri: 'file1',
          },
          region: {
            startLine: 1,
            startColumn: 1,
            endLine: 1,
            endColumn: 1,
          },
        },
        message: {
          text: 'message1',
        },
        ruleId: 'rule1',
      }),
      JSON.stringify({
        physicalLocation: {
          artifactLocation: {
            uri: 'file2',
          },
          region: {
            startLine: 2,
            startColumn: 2,
            endLine: 2,
            endColumn: 2,
          },
        },
        message: {
          text: 'message2',
        },
        ruleId: 'rule2', // duplicated rule is in the other set
      }),
    ]);

    const set2 = new Set([
      JSON.stringify({
        physicalLocation: {
          artifactLocation: {
            uri: 'file3',
          },
          region: {
            startLine: 1,
            startColumn: 1,
            endLine: 1,
            endColumn: 1,
          },
        },
        message: {
          text: 'message1',
        },
        ruleId: 'rule1',
      }),
      JSON.stringify({
        physicalLocation: {
          artifactLocation: {
            uri: 'file2',
          },
          region: {
            startLine: 2,
            startColumn: 2,
            endLine: 2,
            endColumn: 2,
          },
        },
        message: {
          text: 'message2',
        },
        ruleId: 'rule2', // duplicate rule *from* the other set here
      }),
      JSON.stringify({
        physicalLocation: {
          artifactLocation: {
            uri: 'file4',
          },
          region: {
            startLine: 3,
            startColumn: 3,
            endLine: 3,
            endColumn: 3,
          },
        },
        message: {
          text: 'message1',
        },
        ruleId: 'rule1', // duplicate rule *within* this set here
      }),
    ]);

    const [diff] = dedup(difference(set1, set2));
    assert.strictEqual(diff.size, 1);
  });
});
