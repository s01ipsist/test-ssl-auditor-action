import { RulesConfig } from './rules-config';
import { TestSSLResults } from './types';
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
 * Engine for auditing testssl.sh results against rules
 */
export declare class AuditEngine {
  private config;
  constructor(config: RulesConfig);
  /**
   * Helper function to format IP address suffix for messages
   */
  private formatIpSuffix;
  /**
   * Helper function to parse certificate date from testssl.sh format
   * @param dateString Date string in format "YYYY-MM-DD HH:mm"
   * @param isNotAfter Whether this is a notAfter date (adds :59 seconds instead of :00)
   * @returns Parsed Date object or null if invalid
   */
  private parseCertificateDate;
  /**
   * Helper function to check if a finding indicates the protocol/cipher is offered
   * @param finding The finding string from testssl.sh
   * @returns true if the protocol/cipher is offered, false otherwise
   */
  private isOffered;
  /**
   * Audit testssl.sh results against configured rules
   * @param results The testssl.sh JSON results (array of scan items)
   * @returns Array of violations found
   */
  audit(results: TestSSLResults): Violation[];
  /**
   * Get comprehensive audit results for annotations (both pass and fail)
   * @param results The testssl.sh JSON results (array of scan items)
   * @returns Array of audit results with pass/fail status
   */
  getAuditResults(results: TestSSLResults): AuditResult[];
  /**
   * Check overall grade compliance
   */
  private checkOverallGrade;
  /**
   * Check TLS version compliance
   */
  private checkTlsVersion;
  /**
   * Check for blocked ciphers
   */
  private checkBlockedCiphers;
  /**
   * Check for forward secrecy support
   */
  private checkForwardSecrecy;
  /**
   * Get overall grade audit results for annotations
   */
  private getOverallGradeResults;
  /**
   * Get TLS version audit results for annotations
   */
  private getTlsVersionResults;
  /**
   * Get blocked cipher audit results for annotations
   */
  private getBlockedCipherResults;
  /**
   * Get forward secrecy audit results for annotations
   */
  private getForwardSecrecyResults;
  /**
   * Check certificate expiry compliance
   */
  private checkCertificateExpiry;
  /**
   * Get certificate expiry audit results for annotations
   */
  private getCertificateExpiryResults;
}
