import { readFile } from 'fs/promises';
import { existsSync } from 'fs';

/**
 * Configuration for audit rules
 */
export interface RulesConfig {
  rules: {
    minTlsVersion?: string;
    allowedCiphers?: string[];
    blockedCiphers?: string[];
    requireForwardSecrecy?: boolean;
    maxCertificateExpiry?: number; // days
  };
}

/**
 * Default rules configuration
 */
export const DEFAULT_RULES: RulesConfig = {
  rules: {
    minTlsVersion: '1.2',
    allowedCiphers: [],
    blockedCiphers: ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'anon'],
    requireForwardSecrecy: true,
    maxCertificateExpiry: 90
  }
};

/**
 * Load rules configuration from a file
 * @param configPath Path to the configuration file
 * @returns Parsed rules configuration
 */
export async function loadRulesConfig(configPath: string): Promise<RulesConfig> {
  if (!configPath || !existsSync(configPath)) {
    return DEFAULT_RULES;
  }

  const content = await readFile(configPath, 'utf-8');
  const config = JSON.parse(content) as RulesConfig;

  // Merge with defaults
  return {
    rules: {
      ...DEFAULT_RULES.rules,
      ...config.rules
    }
  };
}
