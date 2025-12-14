import * as core from '@actions/core';
import * as glob from '@actions/glob';
import { readFile } from 'fs/promises';
import { AuditEngine } from './audit-engine';
import { RulesConfig, loadRulesConfig, DEFAULT_RULES } from './rules-config';

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
      rulesConfig = DEFAULT_RULES;
    }

    // Process each file
    const auditEngine = new AuditEngine(rulesConfig);
    let totalViolations = 0;

    for (const filePath of files) {
      core.info(`Processing: ${filePath}`);
      try {
        const content = await readFile(filePath, 'utf-8');
        const results = JSON.parse(content);

        // Get audit results for annotations
        const auditResults = auditEngine.getAuditResults(results);

        // Create annotations for each result
        for (const result of auditResults) {
          if (result.passed) {
            core.notice(result.message);
          } else {
            core.error(result.message);
            totalViolations++;
          }
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        core.error(`Failed to process ${filePath}: ${errorMessage}`);
      }
    }

    // Set outputs
    const violationsFound = totalViolations > 0;
    core.setOutput('violations-found', violationsFound.toString());
    core.setOutput('violation-count', totalViolations.toString());
    core.setOutput(
      'summary',
      violationsFound ? `Found ${totalViolations} violations` : 'All checks passed'
    );

    // Fail if requested and violations found
    if (failOnViolation && violationsFound) {
      core.setFailed(`Found ${totalViolations} violations. Review the annotations for details.`);
    } else if (violationsFound) {
      core.warning(
        `Found ${totalViolations} violations but not failing (fail-on-violation is false)`
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
