/**
 * Configuration for audit rules
 */
export interface RulesConfig {
    rules: {
        minTlsVersion?: string;
        allowedCiphers?: string[];
        blockedCiphers?: string[];
        requireForwardSecrecy?: boolean;
        maxCertificateExpiry?: number;
        minGrade?: string;
    };
}
/**
 * Default rules configuration
 */
export declare const DEFAULT_RULES: RulesConfig;
/**
 * Load rules configuration from a file
 * @param configPath Path to the configuration file
 * @returns Parsed rules configuration
 */
export declare function loadRulesConfig(configPath: string): Promise<RulesConfig>;
