import { describe, expect, it } from 'vitest';

import { cell, formatSeverityCounts, formatStepMetrics, truncateText } from './format.js';

describe('truncateText', () => {
  it('leaves short text untouched', () => {
    expect(truncateText('abc', 10)).toEqual({ text: 'abc', truncated: false, totalChars: 3 });
  });

  it('cuts at a line boundary when one is near the limit', () => {
    const text = `${'a'.repeat(90)}\n${'b'.repeat(20)}`;
    expect(truncateText(text, 100)).toEqual({ text: 'a'.repeat(90), truncated: true, totalChars: 111 });
  });

  it('hard-cuts when there is no nearby newline', () => {
    const r = truncateText('x'.repeat(100), 40);
    expect(r.text).toHaveLength(40);
    expect(r.truncated).toBe(true);
  });
});

describe('cell', () => {
  it('escapes pipes, collapses whitespace and clips', () => {
    expect(cell('a | b\n c')).toBe('a \\| b c');
    expect(cell(null)).toBe('-');
    expect(cell('abcdef', 4)).toBe('abc…');
  });
});

describe('formatSeverityCounts', () => {
  it('orders by severity and skips zeros', () => {
    expect(formatSeverityCounts({ LOW: 2, CRITICAL: 1, HIGH: 0 })).toBe('1 critical, 2 low');
    expect(formatSeverityCounts({})).toBe('none');
  });
});

describe('formatStepMetrics', () => {
  it('summarizes test, documentation, sustainability and AI code risk metrics', () => {
    expect(
      formatStepMetrics({
        analyzerId: 'tests',
        metrics: { testFiles: 18, sourceFiles: 120, testRatioPct: 12 },
      }),
    ).toBe('18 test files, 120 source files, test-to-code ratio 12%');
    expect(
      formatStepMetrics({ analyzerId: 'docs', metrics: { docCoveragePct: 25, publicSymbols: 240 } }),
    ).toBe('25% of 240 public symbols documented');
    expect(
      formatStepMetrics({
        analyzerId: 'licenses',
        metrics: { packages: 12, distinctLicenses: 3, projectLicense: 'none' },
      }),
    ).toBe('12 packages, 3 licenses');
    expect(
      formatStepMetrics({ analyzerId: 'dep-health', metrics: { directDependencies: 9, deprecated: 1 } }),
    ).toBe('9 direct dependencies, 1 deprecated');
    expect(
      formatStepMetrics({ analyzerId: 'hallucinated-deps', metrics: { packages: 310, unknown: 0 } }),
    ).toBe('310 packages verified against public registries');
  });

  it('leaves out ratios and history facts that have nothing behind them', () => {
    // Without source files, public symbols or commits, ratios and history summaries are meaningless
    expect(
      formatStepMetrics({ analyzerId: 'tests', metrics: { testFiles: 0, sourceFiles: 0, testRatioPct: 0 } }),
    ).toBe('0 test files, 0 source files');
    expect(
      formatStepMetrics({ analyzerId: 'docs', metrics: { docCoveragePct: 100, publicSymbols: 0 } }),
    ).toBeNull();
    expect(
      formatStepMetrics({ analyzerId: 'activity', metrics: { commitsAnalyzed: 0, busFactor: 0 } }),
    ).toBeNull();
    expect(formatStepMetrics({ analyzerId: 'gitleaks', metrics: { findings: 2 } })).toBeNull();
    // A repository without a manifest has no verified packages
    expect(
      formatStepMetrics({ analyzerId: 'hallucinated-deps', metrics: { packages: 0, unknown: 0 } }),
    ).toBeNull();
  });
});
