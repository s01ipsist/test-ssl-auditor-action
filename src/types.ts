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

// testssl.sh output is actually an array of scan items
export type TestSSLResults = TestSSLScanItem[];
