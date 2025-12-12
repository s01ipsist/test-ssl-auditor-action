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
export declare class AuditEngine {
    private config;
    constructor(config: RulesConfig);
    /**
     * Audit testssl.sh results against configured rules
     * @param results The testssl.sh JSON results
     * @returns Array of violations found
     */
    audit(results: any): Violation[];
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
}
