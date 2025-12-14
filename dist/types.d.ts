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
export type TestSSLResults = TestSSLScanItem[];
