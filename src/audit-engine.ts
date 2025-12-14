import { RulesConfig } from './rules-config';
import { TestSSLResults, TestSSLScanItem } from './types';

/**
 * Represents a rule violation
 */
export interface Violation {
  rule: string;
  message: string;
  details?: Record<string, unknown>;
}

/**
 * Represents an audit result (pass or fail)
 */
export interface AuditResult {
  rule: string;
  passed: boolean;
  message: string;
  details?: Record<string, unknown>;
}

/**
 * Grade ranking for comparison (higher number = better grade)
 */
const GRADE_RANKING: Record<string, number> = {
  'A+': 9,
  A: 8,
  'A-': 7,
  B: 6,
  C: 5,
  D: 4,
  E: 3,
  F: 2,
  T: 1 // Trust issues (e.g., expired certificate)
};

/**
 * Engine for auditing testssl.sh results against rules
 */
export class AuditEngine {
  constructor(private config: RulesConfig) {}

  /**
   * Helper function to format IP address suffix for messages
   */
  private formatIpSuffix(ip?: string): string {
    return ip ? ` [${ip}]` : '';
  }

  /**
   * Helper function to check if a finding indicates the protocol/cipher is offered
   * @param finding The finding string from testssl.sh
   * @returns true if the protocol/cipher is offered, false otherwise
   */
  private isOffered(finding: string): boolean {
    if (!finding) return false;
    // Normalize to lowercase for comparison
    const normalized = finding.toLowerCase();
    // Must NOT contain "not offered" (handle various cases)
    if (normalized.includes('not offered')) return false;
    // Must contain "offered" as a word (not as part of another word like "unoffered")
    // Use word boundary check
    return /\boffered\b/.test(normalized);
  }

  /**
   * Audit testssl.sh results against configured rules
   * @param results The testssl.sh JSON results (array of scan items)
   * @returns Array of violations found
   */
  audit(results: TestSSLResults): Violation[] {
    const violations: Violation[] = [];

    if (!Array.isArray(results)) {
      return violations;
    }

    // Check overall grade
    if (this.config.rules.minGrade) {
      violations.push(...this.checkOverallGrade(results));
    }

    // Check TLS version
    if (this.config.rules.minTlsVersion) {
      violations.push(...this.checkTlsVersion(results));
    }

    // Check ciphers
    if (this.config.rules.blockedCiphers && this.config.rules.blockedCiphers.length > 0) {
      violations.push(...this.checkBlockedCiphers(results));
    }

    // Check forward secrecy
    if (this.config.rules.requireForwardSecrecy) {
      violations.push(...this.checkForwardSecrecy(results));
    }

    return violations;
  }

  /**
   * Get comprehensive audit results for annotations (both pass and fail)
   * @param results The testssl.sh JSON results (array of scan items)
   * @returns Array of audit results with pass/fail status
   */
  getAuditResults(results: TestSSLResults): AuditResult[] {
    const auditResults: AuditResult[] = [];

    if (!Array.isArray(results)) {
      return auditResults;
    }

    // Check overall grade
    if (this.config.rules.minGrade) {
      auditResults.push(...this.getOverallGradeResults(results));
    }

    // Check TLS version
    if (this.config.rules.minTlsVersion) {
      auditResults.push(...this.getTlsVersionResults(results));
    }

    // Check ciphers
    if (this.config.rules.blockedCiphers && this.config.rules.blockedCiphers.length > 0) {
      auditResults.push(...this.getBlockedCipherResults(results));
    }

    // Check forward secrecy
    if (this.config.rules.requireForwardSecrecy) {
      auditResults.push(...this.getForwardSecrecyResults(results));
    }

    return auditResults;
  }

  /**
   * Check overall grade compliance
   */
  private checkOverallGrade(results: TestSSLScanItem[]): Violation[] {
    const violations: Violation[] = [];
    const minGrade = this.config.rules.minGrade;

    if (!minGrade) {
      return violations;
    }

    const gradeItem = results.find(item => item.id === 'overall_grade');

    if (!gradeItem) {
      return violations;
    }

    const actualGrade = gradeItem.finding;
    if (!actualGrade) {
      return violations;
    }

    const minRank = GRADE_RANKING[minGrade];
    const actualRank = GRADE_RANKING[actualGrade];

    if (minRank === undefined) {
      violations.push({
        rule: 'overall-grade',
        message: `Invalid minimum grade specified: ${minGrade}`,
        details: { minGrade, actualGrade }
      });
      return violations;
    }

    if (actualRank === undefined) {
      violations.push({
        rule: 'overall-grade',
        message: `Unknown grade received: ${actualGrade}`,
        details: { minGrade, actualGrade }
      });
      return violations;
    }

    if (actualRank < minRank) {
      violations.push({
        rule: 'overall-grade',
        message: `Overall grade ${actualGrade} does not meet minimum requirement of ${minGrade}`,
        details: { minGrade, actualGrade, minRank, actualRank }
      });
    }

    return violations;
  }

  /**
   * Check TLS version compliance
   */
  private checkTlsVersion(results: TestSSLScanItem[]): Violation[] {
    const violations: Violation[] = [];
    const minVersion = this.config.rules.minTlsVersion;

    if (!minVersion) {
      return violations;
    }

    // Parse minimum version (e.g., "1.2" -> 1.2)
    const minVersionNum = parseFloat(minVersion);

    // Find all TLS protocol entries
    // Pattern matches: TLS1, TLS1_1, TLS1_2, TLS1_3 (testssl.sh naming convention)
    const tlsProtocols = results.filter(
      item => item.id && /^TLS1(_\d+)?$/.test(item.id) && item.finding
    );

    for (const protocol of tlsProtocols) {
      const finding = protocol.finding || '';

      // Check if the protocol is offered using helper function
      if (this.isOffered(finding)) {
        // Extract version number from protocol id (e.g., "TLS1" -> 1.0, "TLS1_2" -> 1.2)
        const match = protocol.id.match(/^TLS1(?:_(\d+))?$/);
        if (match) {
          // TLS1 = 1.0, TLS1_1 = 1.1, TLS1_2 = 1.2, TLS1_3 = 1.3
          const versionNum = match[1] ? parseFloat(`1.${match[1]}`) : 1.0;

          if (versionNum < minVersionNum) {
            violations.push({
              rule: 'min-tls-version',
              message: `Insecure TLS version ${protocol.id.replace('_', '.')} is enabled (finding: "${finding}", minimum required: TLS ${minVersion})${this.formatIpSuffix(protocol.ip)}`,
              details: {
                protocol: protocol.id,
                finding: finding,
                version: versionNum,
                ip: protocol.ip
              }
            });
          }
        }
      }
    }

    return violations;
  }

  /**
   * Check for blocked ciphers
   */
  private checkBlockedCiphers(results: TestSSLScanItem[]): Violation[] {
    const violations: Violation[] = [];
    const blockedCiphers = this.config.rules.blockedCiphers || [];

    if (blockedCiphers.length === 0) {
      return violations;
    }

    // Find cipher list entries (e.g., cipherlist_3DES_IDEA, cipherlist_NULL, etc.)
    const cipherItems = results.filter(
      item => item.id && item.id.startsWith('cipherlist_') && item.finding
    );

    for (const item of cipherItems) {
      const finding = item.finding || '';

      // Only flag if the cipher is offered using helper function
      if (this.isOffered(finding)) {
        const cipherName = item.id.replace('cipherlist_', '');

        for (const blocked of blockedCiphers) {
          if (cipherName.toUpperCase().includes(blocked.toUpperCase())) {
            violations.push({
              rule: 'blocked-cipher',
              message: `Blocked cipher suite detected: ${cipherName} (finding: "${finding}")${this.formatIpSuffix(item.ip)}`,
              details: { cipher: cipherName, blocked: blocked, id: item.id, ip: item.ip }
            });
            break; // Only report once per cipher
          }
        }
      }
    }

    return violations;
  }

  /**
   * Check for forward secrecy support
   */
  private checkForwardSecrecy(results: TestSSLScanItem[]): Violation[] {
    const violations: Violation[] = [];

    // Look for PFS (Perfect Forward Secrecy) related items
    const fsItem = results.find(item => item.id && item.id.toLowerCase().includes('pfs'));

    if (fsItem) {
      // Check if severity is not OK or finding indicates a problem
      if (fsItem.severity && fsItem.severity !== 'OK' && fsItem.severity !== 'INFO') {
        violations.push({
          rule: 'forward-secrecy',
          message: `Forward secrecy is not properly configured${this.formatIpSuffix(fsItem.ip)}`,
          details: { finding: fsItem.finding, severity: fsItem.severity, ip: fsItem.ip }
        });
      }
    }

    return violations;
  }

  /**
   * Get overall grade audit results for annotations
   */
  private getOverallGradeResults(results: TestSSLScanItem[]): AuditResult[] {
    const auditResults: AuditResult[] = [];
    const minGrade = this.config.rules.minGrade;

    if (!minGrade) {
      return auditResults;
    }

    const gradeItem = results.find(item => item.id === 'overall_grade');

    if (!gradeItem) {
      return auditResults;
    }

    const actualGrade = gradeItem.finding;
    if (!actualGrade) {
      return auditResults;
    }

    const minRank = GRADE_RANKING[minGrade];
    const actualRank = GRADE_RANKING[actualGrade];

    if (minRank === undefined) {
      auditResults.push({
        rule: 'overall-grade',
        passed: false,
        message: `Invalid minimum grade specified: ${minGrade}`,
        details: { minGrade, actualGrade }
      });
      return auditResults;
    }

    if (actualRank === undefined) {
      auditResults.push({
        rule: 'overall-grade',
        passed: false,
        message: `Unknown grade received: ${actualGrade}`,
        details: { minGrade, actualGrade }
      });
      return auditResults;
    }

    if (actualRank < minRank) {
      auditResults.push({
        rule: 'overall-grade',
        passed: false,
        message: `Overall grade ${actualGrade} does not meet minimum requirement of ${minGrade}`,
        details: { minGrade, actualGrade, minRank, actualRank }
      });
    } else {
      auditResults.push({
        rule: 'overall-grade',
        passed: true,
        message: `Grade ${actualGrade} meets the minimum requirement of ${minGrade}`,
        details: { minGrade, actualGrade, minRank, actualRank }
      });
    }

    return auditResults;
  }

  /**
   * Get TLS version audit results for annotations
   */
  private getTlsVersionResults(results: TestSSLScanItem[]): AuditResult[] {
    const auditResults: AuditResult[] = [];
    const minVersion = this.config.rules.minTlsVersion;

    if (!minVersion) {
      return auditResults;
    }

    // Parse minimum version (e.g., "1.2" -> 1.2)
    const minVersionNum = parseFloat(minVersion);

    // Find all TLS protocol entries
    const tlsProtocols = results.filter(
      item => item.id && /^TLS1(_\d+)?$/.test(item.id) && item.finding
    );

    for (const protocol of tlsProtocols) {
      const finding = protocol.finding || '';
      const match = protocol.id.match(/^TLS1(?:_(\d+))?$/);
      if (!match) continue;

      const versionNum = match[1] ? parseFloat(`1.${match[1]}`) : 1.0;
      const ipSuffix = this.formatIpSuffix(protocol.ip);

      // Check if the protocol is offered
      if (this.isOffered(finding)) {
        if (versionNum < minVersionNum) {
          auditResults.push({
            rule: 'min-tls-version',
            passed: false,
            message: `Insecure TLS version ${protocol.id.replace('_', '.')} is enabled (finding: "${finding}", minimum required: TLS ${minVersion})${ipSuffix}`,
            details: {
              protocol: protocol.id,
              finding: finding,
              version: versionNum,
              ip: protocol.ip
            }
          });
        } else {
          auditResults.push({
            rule: 'min-tls-version',
            passed: true,
            message: `TLS version ${protocol.id.replace('_', '.')} meets the minimum requirement of TLS ${minVersion}${ipSuffix}`,
            details: {
              protocol: protocol.id,
              finding: finding,
              version: versionNum,
              ip: protocol.ip
            }
          });
        }
      } else {
        // Not offered - this is good for versions below minimum
        if (versionNum < minVersionNum) {
          auditResults.push({
            rule: 'min-tls-version',
            passed: true,
            message: `TLS version ${protocol.id.replace('_', '.')} is not offered (finding: "${finding}")${ipSuffix}`,
            details: {
              protocol: protocol.id,
              finding: finding,
              version: versionNum,
              ip: protocol.ip
            }
          });
        }
      }
    }

    return auditResults;
  }

  /**
   * Get blocked cipher audit results for annotations
   */
  private getBlockedCipherResults(results: TestSSLScanItem[]): AuditResult[] {
    const auditResults: AuditResult[] = [];
    const blockedCiphers = this.config.rules.blockedCiphers || [];

    if (blockedCiphers.length === 0) {
      return auditResults;
    }

    // Find cipher list entries
    const cipherItems = results.filter(
      item => item.id && item.id.startsWith('cipherlist_') && item.finding
    );

    for (const item of cipherItems) {
      const finding = item.finding || '';
      const cipherName = item.id.replace('cipherlist_', '');
      const ipSuffix = this.formatIpSuffix(item.ip);

      // Check if this is a blocked cipher
      let isBlocked = false;
      let blockedPattern = '';
      for (const blocked of blockedCiphers) {
        if (cipherName.toUpperCase().includes(blocked.toUpperCase())) {
          isBlocked = true;
          blockedPattern = blocked;
          break;
        }
      }

      if (isBlocked) {
        // Only flag if the cipher is offered
        if (this.isOffered(finding)) {
          auditResults.push({
            rule: 'blocked-cipher',
            passed: false,
            message: `Blocked cipher suite detected: ${cipherName} (finding: "${finding}")${ipSuffix}`,
            details: { cipher: cipherName, blocked: blockedPattern, id: item.id, ip: item.ip }
          });
        } else {
          auditResults.push({
            rule: 'blocked-cipher',
            passed: true,
            message: `Blocked cipher suite ${cipherName} is not offered (finding: "${finding}")${ipSuffix}`,
            details: { cipher: cipherName, blocked: blockedPattern, id: item.id, ip: item.ip }
          });
        }
      }
    }

    return auditResults;
  }

  /**
   * Get forward secrecy audit results for annotations
   */
  private getForwardSecrecyResults(results: TestSSLScanItem[]): AuditResult[] {
    const auditResults: AuditResult[] = [];

    // Look for PFS (Perfect Forward Secrecy) related items
    const fsItem = results.find(item => item.id && item.id.toLowerCase().includes('pfs'));

    if (fsItem) {
      const ipSuffix = this.formatIpSuffix(fsItem.ip);
      // Check if severity is not OK or finding indicates a problem
      if (fsItem.severity && fsItem.severity !== 'OK' && fsItem.severity !== 'INFO') {
        auditResults.push({
          rule: 'forward-secrecy',
          passed: false,
          message: `Forward secrecy is not properly configured${ipSuffix}`,
          details: { finding: fsItem.finding, severity: fsItem.severity, ip: fsItem.ip }
        });
      } else {
        auditResults.push({
          rule: 'forward-secrecy',
          passed: true,
          message: `Forward secrecy is properly configured${ipSuffix}`,
          details: { finding: fsItem.finding, severity: fsItem.severity, ip: fsItem.ip }
        });
      }
    }

    return auditResults;
  }
}
