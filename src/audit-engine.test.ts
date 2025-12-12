import { AuditEngine } from './audit-engine';
import { RulesConfig } from './rules-config';

describe('AuditEngine', () => {
  let engine: AuditEngine;
  let config: RulesConfig;

  beforeEach(() => {
    config = {
      rules: {
        minTlsVersion: '1.2',
        blockedCiphers: ['RC4', 'DES', '3DES'],
        requireForwardSecrecy: true
      }
    };
    engine = new AuditEngine(config);
  });

  describe('audit', () => {
    it('should return empty array when no violations found', () => {
      const mockResults = {
        scanResult: [
          {
            id: 'TLS1_3',
            severity: 'OK',
            finding: 'offered'
          }
        ]
      };

      const violations = engine.audit(mockResults);
      expect(violations).toEqual([]);
    });

    it('should detect insecure TLS version', () => {
      const mockResults = {
        scanResult: [
          {
            id: 'TLS1_0',
            severity: 'OK',
            finding: 'offered'
          }
        ]
      };

      const violations = engine.audit(mockResults);
      expect(violations.length).toBeGreaterThan(0);
      expect(violations[0].rule).toBe('min-tls-version');
      expect(violations[0].severity).toBe('high');
    });

    it('should detect blocked ciphers', () => {
      const mockResults = {
        scanResult: [
          {
            id: 'cipher_test',
            finding: 'RC4-SHA'
          }
        ]
      };

      const violations = engine.audit(mockResults);
      expect(violations.length).toBeGreaterThan(0);
      expect(violations[0].rule).toBe('blocked-cipher');
      expect(violations[0].severity).toBe('critical');
    });

    it('should handle array of scan results', () => {
      const mockResults = [
        {
          scanResult: [
            {
              id: 'TLS1_0',
              severity: 'OK',
              finding: 'offered'
            }
          ]
        }
      ];

      const violations = engine.audit(mockResults);
      expect(violations.length).toBeGreaterThan(0);
    });

    it('should handle missing scanResult gracefully', () => {
      const mockResults = {};
      const violations = engine.audit(mockResults);
      expect(violations).toEqual([]);
    });
  });
});
