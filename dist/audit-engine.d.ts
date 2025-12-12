import { RulesConfig } from './rules-config';
import { TestSSLResults } from './types';
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
}
