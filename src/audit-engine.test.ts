import { AuditEngine } from './audit-engine';
import { RulesConfig } from './rules-config';
import { TestSSLScanItem } from './types';

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
      const mockResults: TestSSLScanItem[] = [
        {
          id: 'TLS1_3',
          severity: 'OK',
          finding: 'offered'
        },
        {
          id: 'TLS1_2',
          severity: 'OK',
          finding: 'offered'
        }
      ];

      const violations = engine.audit(mockResults);
      expect(violations).toEqual([]);
    });

    it('should detect insecure TLS version when offered', () => {
      const mockResults: TestSSLScanItem[] = [
        {
          id: 'TLS1',
          severity: 'LOW',
          finding: 'offered (deprecated)'
        }
      ];

      const violations = engine.audit(mockResults);
      expect(violations.length).toBeGreaterThan(0);
      expect(violations[0].rule).toBe('min-tls-version');
      expect(violations[0].message).toContain('TLS1');
    });

    it('should not flag TLS versions that are not offered', () => {
      const mockResults: TestSSLScanItem[] = [
        {
          id: 'TLS1',
          severity: 'OK',
          finding: 'not offered'
        }
      ];

      const violations = engine.audit(mockResults);
      expect(violations).toEqual([]);
    });

    it('should detect blocked ciphers when offered', () => {
      const mockResults: TestSSLScanItem[] = [
        {
          id: 'cipherlist_3DES_IDEA',
          severity: 'MEDIUM',
          finding: 'offered'
        }
      ];

      const violations = engine.audit(mockResults);
      expect(violations.length).toBeGreaterThan(0);
      expect(violations[0].rule).toBe('blocked-cipher');
      expect(violations[0].message).toContain('3DES');
    });

    it('should not flag blocked ciphers when not offered', () => {
      const mockResults: TestSSLScanItem[] = [
        {
          id: 'cipherlist_RC4',
          severity: 'OK',
          finding: 'not offered'
        }
      ];

      const violations = engine.audit(mockResults);
      expect(violations).toEqual([]);
    });

    it('should handle missing scanResult gracefully', () => {
      const mockResults: TestSSLScanItem[] = [];
      const violations = engine.audit(mockResults);
      expect(violations).toEqual([]);
    });
  });

  describe('overall grade', () => {
    it('should detect grade below minimum requirement', () => {
      const configWithGrade: RulesConfig = {
        rules: {
          minGrade: 'A'
        }
      };
      const engineWithGrade = new AuditEngine(configWithGrade);

      const mockResults: TestSSLScanItem[] = [
        {
          id: 'overall_grade',
          severity: 'MEDIUM',
          finding: 'B'
        }
      ];

      const violations = engineWithGrade.audit(mockResults);
      expect(violations.length).toBeGreaterThan(0);
      expect(violations[0].rule).toBe('overall-grade');
      expect(violations[0].message).toContain('does not meet minimum');
    });

    it('should pass when grade meets minimum requirement', () => {
      const configWithGrade: RulesConfig = {
        rules: {
          minGrade: 'B'
        }
      };
      const engineWithGrade = new AuditEngine(configWithGrade);

      const mockResults: TestSSLScanItem[] = [
        {
          id: 'overall_grade',
          severity: 'OK',
          finding: 'A'
        }
      ];

      const violations = engineWithGrade.audit(mockResults);
      expect(violations).toEqual([]);
    });

    it('should handle grade T (trust issues) as critical', () => {
      const configWithGrade: RulesConfig = {
        rules: {
          minGrade: 'C'
        }
      };
      const engineWithGrade = new AuditEngine(configWithGrade);

      const mockResults: TestSSLScanItem[] = [
        {
          id: 'overall_grade',
          severity: 'CRITICAL',
          finding: 'T'
        }
      ];

      const violations = engineWithGrade.audit(mockResults);
      expect(violations.length).toBeGreaterThan(0);
      expect(violations[0].rule).toBe('overall-grade');
    });

    it('should handle A+ grade correctly', () => {
      const configWithGrade: RulesConfig = {
        rules: {
          minGrade: 'A+'
        }
      };
      const engineWithGrade = new AuditEngine(configWithGrade);

      const mockResults: TestSSLScanItem[] = [
        {
          id: 'overall_grade',
          severity: 'OK',
          finding: 'A+'
        }
      ];

      const violations = engineWithGrade.audit(mockResults);
      expect(violations).toEqual([]);
    });

    it('should handle A- grade below A requirement', () => {
      const configWithGrade: RulesConfig = {
        rules: {
          minGrade: 'A'
        }
      };
      const engineWithGrade = new AuditEngine(configWithGrade);

      const mockResults: TestSSLScanItem[] = [
        {
          id: 'overall_grade',
          severity: 'OK',
          finding: 'A-'
        }
      ];

      const violations = engineWithGrade.audit(mockResults);
      expect(violations.length).toBeGreaterThan(0);
    });

    it('should not check grade when minGrade is not configured', () => {
      const mockResults: TestSSLScanItem[] = [
        {
          id: 'overall_grade',
          severity: 'MEDIUM',
          finding: 'F'
        }
      ];

      const violations = engine.audit(mockResults);
      // Should not have grade violations since minGrade is not set
      const gradeViolations = violations.filter(v => v.rule === 'overall-grade');
      expect(gradeViolations).toEqual([]);
    });
  });

  describe('edge cases', () => {
    it('should not match "unoffered" as offered', () => {
      const mockResults: TestSSLScanItem[] = [
        {
          id: 'TLS1',
          severity: 'OK',
          finding: 'unoffered'
        }
      ];

      const violations = engine.audit(mockResults);
      expect(violations).toEqual([]);
    });

    it('should handle "not offered + downgraded to weaker protocol"', () => {
      const mockResults: TestSSLScanItem[] = [
        {
          id: 'TLS1_3',
          severity: 'INFO',
          finding: 'not offered + downgraded to weaker protocol'
        }
      ];

      const violations = engine.audit(mockResults);
      expect(violations).toEqual([]);
    });
  });
});
