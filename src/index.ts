import * as core from '@actions/core';
import * as glob from '@actions/glob';
import { readFile } from 'fs/promises';
import { AuditEngine } from './audit-engine';
import { RulesConfig, loadRulesConfig } from './rules-config';

/**
 * Main entry point for the GitHub Action
 */
async function run(): Promise<void> {
  try {
    // Get inputs
    const resultsPath = core.getInput('results-path', { required: true });
    const rulesConfigPath = core.getInput('rules-config', { required: false });
    const failOnViolation = core.getInput('fail-on-violation', { required: false }) === 'true';

    core.info(`Searching for testssl.sh results: ${resultsPath}`);

    // Find all matching files
    const globber = await glob.create(resultsPath);
    const files = await globber.glob();

    if (files.length === 0) {
      core.warning(`No files found matching pattern: ${resultsPath}`);
      core.setOutput('violations-found', 'false');
      core.setOutput('violation-count', '0');
      core.setOutput('summary', 'No testssl.sh result files found');
      return;
    }

    core.info(`Found ${files.length} file(s) to audit`);

    // Load rules configuration
    let rulesConfig: RulesConfig;
    try {
      rulesConfig = await loadRulesConfig(rulesConfigPath);
      core.info(`Loaded rules configuration from: ${rulesConfigPath}`);
    } catch (error) {
      core.warning(`Could not load rules config from ${rulesConfigPath}, using defaults`);
      rulesConfig = {
        rules: {
          minTlsVersion: '1.2',
          allowedCiphers: [],
          blockedCiphers: [],
          requireForwardSecrecy: true
        }
      };
    }

    // Process each file
    const auditEngine = new AuditEngine(rulesConfig);
    let totalViolations = 0;
    const summaryLines: string[] = [];

    for (const filePath of files) {
      core.info(`Processing: ${filePath}`);
      try {
        const content = await readFile(filePath, 'utf-8');
        const results = JSON.parse(content);
        const violations = auditEngine.audit(results);

        if (violations.length > 0) {
          core.warning(`Found ${violations.length} violation(s) in ${filePath}`);
          violations.forEach(violation => {
            core.warning(`  - ${violation.message}`);
          });
          totalViolations += violations.length;
          summaryLines.push(`${filePath}: ${violations.length} violation(s)`);
        } else {
          core.info(`No violations found in ${filePath}`);
          summaryLines.push(`${filePath}: PASS`);
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        core.error(`Failed to process ${filePath}: ${errorMessage}`);
        summaryLines.push(`${filePath}: ERROR - ${errorMessage}`);
      }
    }

    // Set outputs
    const violationsFound = totalViolations > 0;
    core.setOutput('violations-found', violationsFound.toString());
    core.setOutput('violation-count', totalViolations.toString());
    core.setOutput('summary', summaryLines.join('\n'));

    // Summary
    core.summary
      .addHeading('SSL Audit Results')
      .addRaw(`Processed ${files.length} file(s)`)
      .addBreak()
      .addRaw(`Total violations: ${totalViolations}`)
      .addBreak()
      .addBreak()
      .addHeading('Details', 3);

    summaryLines.forEach(line => {
      core.summary.addRaw(line).addBreak();
    });

    await core.summary.write();

    // Fail if requested and violations found
    if (failOnViolation && violationsFound) {
      core.setFailed(`Found ${totalViolations} rule violation(s). Review the logs for details.`);
    } else if (violationsFound) {
      core.warning(
        `Found ${totalViolations} rule violation(s) but not failing (fail-on-violation is false)`
      );
    } else {
      core.info('✅ All audits passed!');
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    core.setFailed(`Action failed: ${errorMessage}`);
  }
}

// Run the action
run();
