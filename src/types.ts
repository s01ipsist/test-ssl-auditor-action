/**
 * Type definitions for testssl.sh JSON output
 */

export interface TestSSLScanItem {
  id: string;
  ip?: string;
  port?: string;
  severity?: string;
  finding?: string;
  cve?: string;
  cwe?: string;
}

export interface TestSSLResult {
  scanResult?: TestSSLScanItem[];
  invocation?: string;
  at?: string;
  version?: string;
  openssl?: string;
  startTime?: string;
  scanTime?: string;
}

export type TestSSLResults = TestSSLResult | TestSSLResult[];
