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

  describe('selective rule testing', () => {
    it('should only test minGrade when only minGrade is configured', () => {
      // Config with only minGrade set (issue example)
      const configWithOnlyGrade: RulesConfig = {
        rules: {
          minGrade: 'B'
        }
      };
      const engineWithOnlyGrade = new AuditEngine(configWithOnlyGrade);

      const mockResults: TestSSLScanItem[] = [
        {
          id: 'overall_grade',
          severity: 'OK',
          finding: 'A'
        },
        {
          id: 'TLS1',
          severity: 'LOW',
          finding: 'offered (deprecated)'
        },
        {
          id: 'cipherlist_RC4',
          severity: 'HIGH',
          finding: 'offered'
        }
      ];

      const violations = engineWithOnlyGrade.audit(mockResults);

      // Should not have any violations because:
      // - Grade A meets minimum of B (passes)
      // - TLS1 should not be checked (minTlsVersion not configured)
      // - RC4 cipher should not be checked (blockedCiphers not configured)
      expect(violations).toEqual([]);
    });

    it('should test all configured rules when multiple rules are set', () => {
      const configWithMultiple: RulesConfig = {
        rules: {
          minGrade: 'A',
          minTlsVersion: '1.2'
        }
      };
      const engineWithMultiple = new AuditEngine(configWithMultiple);

      const mockResults: TestSSLScanItem[] = [
        {
          id: 'overall_grade',
          severity: 'MEDIUM',
          finding: 'B'
        },
        {
          id: 'TLS1',
          severity: 'LOW',
          finding: 'offered (deprecated)'
        }
      ];

      const violations = engineWithMultiple.audit(mockResults);

      // Should have violations for both rules
      expect(violations.length).toBe(2);
      expect(violations.some(v => v.rule === 'overall-grade')).toBe(true);
      expect(violations.some(v => v.rule === 'min-tls-version')).toBe(true);
    });

    it('should not test unconfigured rules even with potential violations', () => {
      // Only configure blockedCiphers
      const configWithOnlyCiphers: RulesConfig = {
        rules: {
          blockedCiphers: ['RC4']
        }
      };
      const engineWithOnlyCiphers = new AuditEngine(configWithOnlyCiphers);

      const mockResults: TestSSLScanItem[] = [
        {
          id: 'overall_grade',
          severity: 'CRITICAL',
          finding: 'F'
        },
        {
          id: 'TLS1',
          severity: 'LOW',
          finding: 'offered (deprecated)'
        },
        {
          id: 'cipherlist_RC4',
          severity: 'HIGH',
          finding: 'offered'
        }
      ];

      const violations = engineWithOnlyCiphers.audit(mockResults);

      // Should only have violation for RC4 cipher
      expect(violations.length).toBe(1);
      expect(violations[0].rule).toBe('blocked-cipher');
      // Should NOT flag grade F or TLS1 as those rules are not configured
    });
  });

  describe('certificate expiry', () => {
    it('should detect expired certificates', () => {
      const configWithExpiry: RulesConfig = {
        rules: {
          maxCertificateExpiry: 30
        }
      };
      const engineWithExpiry = new AuditEngine(configWithExpiry);

      const mockResults: TestSSLScanItem[] = [
        {
          id: 'cert_notBefore',
          ip: 'expired.badssl.com/104.154.89.105',
          port: '443',
          severity: 'INFO',
          finding: '2015-04-09 00:00'
        },
        {
          id: 'cert_notAfter',
          ip: 'expired.badssl.com/104.154.89.105',
          port: '443',
          severity: 'CRITICAL',
          finding: '2015-04-12 23:59'
        }
      ];

      const violations = engineWithExpiry.audit(mockResults);
      expect(violations.length).toBeGreaterThan(0);
      expect(violations[0].rule).toBe('certificate-expiry');
      expect(violations[0].message).toContain('expired');
    });

    it('should detect certificates expiring within threshold', () => {
      const configWithExpiry: RulesConfig = {
        rules: {
          maxCertificateExpiry: 30
        }
      };
      const engineWithExpiry = new AuditEngine(configWithExpiry);

      // Create a certificate that expires in 15 days
      const now = new Date();
      const notBefore = new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000); // 1 year ago
      const notAfter = new Date(now.getTime() + 15 * 24 * 60 * 60 * 1000); // 15 days from now

      const formatDate = (date: Date) => {
        const year = date.getUTCFullYear();
        const month = String(date.getUTCMonth() + 1).padStart(2, '0');
        const day = String(date.getUTCDate()).padStart(2, '0');
        const hours = String(date.getUTCHours()).padStart(2, '0');
        const minutes = String(date.getUTCMinutes()).padStart(2, '0');
        return `${year}-${month}-${day} ${hours}:${minutes}`;
      };

      const mockResults: TestSSLScanItem[] = [
        {
          id: 'cert_notBefore',
          ip: 'example.com/1.2.3.4',
          port: '443',
          severity: 'INFO',
          finding: formatDate(notBefore)
        },
        {
          id: 'cert_notAfter',
          ip: 'example.com/1.2.3.4',
          port: '443',
          severity: 'WARN',
          finding: formatDate(notAfter)
        }
      ];

      const violations = engineWithExpiry.audit(mockResults);
      expect(violations.length).toBeGreaterThan(0);
      expect(violations[0].rule).toBe('certificate-expiry');
      expect(violations[0].message).toContain('expires in');
      expect(violations[0].message).toContain('15 days');
    });

    it('should pass for valid certificates not expiring soon', () => {
      const configWithExpiry: RulesConfig = {
        rules: {
          maxCertificateExpiry: 30
        }
      };
      const engineWithExpiry = new AuditEngine(configWithExpiry);

      // Create a certificate that expires in 90 days
      const now = new Date();
      const notBefore = new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000); // 1 year ago
      const notAfter = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000); // 90 days from now

      const formatDate = (date: Date) => {
        const year = date.getUTCFullYear();
        const month = String(date.getUTCMonth() + 1).padStart(2, '0');
        const day = String(date.getUTCDate()).padStart(2, '0');
        const hours = String(date.getUTCHours()).padStart(2, '0');
        const minutes = String(date.getUTCMinutes()).padStart(2, '0');
        return `${year}-${month}-${day} ${hours}:${minutes}`;
      };

      const mockResults: TestSSLScanItem[] = [
        {
          id: 'cert_notBefore',
          ip: 'example.com/1.2.3.4',
          port: '443',
          severity: 'INFO',
          finding: formatDate(notBefore)
        },
        {
          id: 'cert_notAfter',
          ip: 'example.com/1.2.3.4',
          port: '443',
          severity: 'OK',
          finding: formatDate(notAfter)
        }
      ];

      const violations = engineWithExpiry.audit(mockResults);
      expect(violations).toEqual([]);
    });

    it('should detect certificates not yet valid', () => {
      const configWithExpiry: RulesConfig = {
        rules: {
          maxCertificateExpiry: 30
        }
      };
      const engineWithExpiry = new AuditEngine(configWithExpiry);

      // Create a certificate that is not yet valid (notBefore in the future)
      const now = new Date();
      const notBefore = new Date(now.getTime() + 10 * 24 * 60 * 60 * 1000); // 10 days from now
      const notAfter = new Date(now.getTime() + 100 * 24 * 60 * 60 * 1000); // 100 days from now

      const formatDate = (date: Date) => {
        const year = date.getUTCFullYear();
        const month = String(date.getUTCMonth() + 1).padStart(2, '0');
        const day = String(date.getUTCDate()).padStart(2, '0');
        const hours = String(date.getUTCHours()).padStart(2, '0');
        const minutes = String(date.getUTCMinutes()).padStart(2, '0');
        return `${year}-${month}-${day} ${hours}:${minutes}`;
      };

      const mockResults: TestSSLScanItem[] = [
        {
          id: 'cert_notBefore',
          ip: 'example.com/1.2.3.4',
          port: '443',
          severity: 'CRITICAL',
          finding: formatDate(notBefore)
        },
        {
          id: 'cert_notAfter',
          ip: 'example.com/1.2.3.4',
          port: '443',
          severity: 'OK',
          finding: formatDate(notAfter)
        }
      ];

      const violations = engineWithExpiry.audit(mockResults);
      expect(violations.length).toBeGreaterThan(0);
      expect(violations[0].rule).toBe('certificate-expiry');
      expect(violations[0].message).toContain('not yet valid');
    });

    it('should handle missing certificate data gracefully', () => {
      const configWithExpiry: RulesConfig = {
        rules: {
          maxCertificateExpiry: 30
        }
      };
      const engineWithExpiry = new AuditEngine(configWithExpiry);

      const mockResults: TestSSLScanItem[] = [
        {
          id: 'some_other_item',
          severity: 'OK',
          finding: 'test'
        }
      ];

      const violations = engineWithExpiry.audit(mockResults);
      // Should not have certificate violations when cert data is missing
      const certViolations = violations.filter(v => v.rule === 'certificate-expiry');
      expect(certViolations).toEqual([]);
    });

    it('should not check certificate expiry when maxCertificateExpiry is not configured', () => {
      const configWithoutExpiry: RulesConfig = {
        rules: {
          minTlsVersion: '1.2'
        }
      };
      const engineWithoutExpiry = new AuditEngine(configWithoutExpiry);

      const mockResults: TestSSLScanItem[] = [
        {
          id: 'cert_notBefore',
          ip: 'expired.badssl.com/104.154.89.105',
          port: '443',
          severity: 'INFO',
          finding: '2015-04-09 00:00'
        },
        {
          id: 'cert_notAfter',
          ip: 'expired.badssl.com/104.154.89.105',
          port: '443',
          severity: 'CRITICAL',
          finding: '2015-04-12 23:59'
        }
      ];

      const violations = engineWithoutExpiry.audit(mockResults);
      // Should not have certificate violations when rule is not configured
      const certViolations = violations.filter(v => v.rule === 'certificate-expiry');
      expect(certViolations).toEqual([]);
    });
  });
});
