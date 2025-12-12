import { RulesConfig } from './rules-config';

/**
 * Represents a rule violation
 */
export interface Violation {
  rule: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
  details?: Record<string, unknown>;
}

/**
 * Engine for auditing testssl.sh results against rules
 */
export class AuditEngine {
  constructor(private config: RulesConfig) {}

  /**
   * Audit testssl.sh results against configured rules
   * @param results The testssl.sh JSON results
   * @returns Array of violations found
   */
  audit(results: any): Violation[] {
    const violations: Violation[] = [];

    // Handle both single scan and array of scans
    const scans = Array.isArray(results) ? results : [results];

    for (const scan of scans) {
      if (!scan || typeof scan !== 'object') {
        continue;
      }

      // Check TLS version
      if (this.config.rules.minTlsVersion) {
        violations.push(...this.checkTlsVersion(scan));
      }

      // Check ciphers
      if (this.config.rules.blockedCiphers && this.config.rules.blockedCiphers.length > 0) {
        violations.push(...this.checkBlockedCiphers(scan));
      }

      // Check forward secrecy
      if (this.config.rules.requireForwardSecrecy) {
        violations.push(...this.checkForwardSecrecy(scan));
      }
    }

    return violations;
  }

  /**
   * Check TLS version compliance
   */
  private checkTlsVersion(scan: any): Violation[] {
    const violations: Violation[] = [];
    const minVersion = this.config.rules.minTlsVersion;

    if (!minVersion) {
      return violations;
    }

    // Parse minimum version (e.g., "1.2" -> 1.2)
    const minVersionNum = parseFloat(minVersion);

    // Check protocols in the scan results
    if (scan.scanResult && Array.isArray(scan.scanResult)) {
      const protocols = scan.scanResult.filter((item: any) => item.id && item.id.startsWith('TLS'));

      for (const protocol of protocols) {
        if (protocol.severity === 'OK' || protocol.finding === 'offered') {
          // Extract version from protocol (e.g., "TLS 1.0" -> 1.0)
          const match = protocol.id.match(/TLS1?[_.]?(\d+)/i);
          if (match) {
            const versionNum = parseFloat(`1.${match[1]}`);
            if (versionNum < minVersionNum) {
              violations.push({
                rule: 'min-tls-version',
                severity: 'high',
                message: `Insecure TLS version ${protocol.id} is enabled (minimum required: TLS ${minVersion})`,
                details: { protocol: protocol.id }
              });
            }
          }
        }
      }
    }

    return violations;
  }

  /**
   * Check for blocked ciphers
   */
  private checkBlockedCiphers(scan: any): Violation[] {
    const violations: Violation[] = [];
    const blockedCiphers = this.config.rules.blockedCiphers || [];

    if (blockedCiphers.length === 0) {
      return violations;
    }

    // Check for ciphers in scan results
    if (scan.scanResult && Array.isArray(scan.scanResult)) {
      const cipherItems = scan.scanResult.filter(
        (item: any) => item.id && item.id.includes('cipher')
      );

      for (const item of cipherItems) {
        const cipherName = item.finding || item.id;
        if (typeof cipherName === 'string') {
          for (const blocked of blockedCiphers) {
            if (cipherName.toLowerCase().includes(blocked.toLowerCase())) {
              violations.push({
                rule: 'blocked-cipher',
                severity: 'critical',
                message: `Blocked cipher detected: ${cipherName}`,
                details: { cipher: cipherName, blocked: blocked }
              });
            }
          }
        }
      }
    }

    return violations;
  }

  /**
   * Check for forward secrecy support
   */
  private checkForwardSecrecy(scan: any): Violation[] {
    const violations: Violation[] = [];

    if (scan.scanResult && Array.isArray(scan.scanResult)) {
      const fsItem = scan.scanResult.find(
        (item: any) => item.id && item.id.toLowerCase().includes('pfs')
      );

      if (fsItem && fsItem.severity !== 'OK') {
        violations.push({
          rule: 'forward-secrecy',
          severity: 'medium',
          message: 'Forward secrecy is not properly configured',
          details: { finding: fsItem.finding }
        });
      }
    }

    return violations;
  }
}
