import { AuditEngine } from '../src/audit-engine';
import { RulesConfig } from '../src/rules-config';
import { TestSSLScanItem } from '../src/types';

describe('AuditEngine - getAuditResults', () => {
  let engine: AuditEngine;
  let config: RulesConfig;

  beforeEach(() => {
    config = {
      rules: {
        minTlsVersion: '1.2',
        blockedCiphers: ['RC4', 'DES', '3DES'],
        requireForwardSecrecy: false,
        minGrade: 'A'
      }
    };
    engine = new AuditEngine(config);
  });

  it('should return pass result for grade meeting requirement', () => {
    const mockResults: TestSSLScanItem[] = [
      {
        id: 'overall_grade',
        finding: 'A+',
        severity: 'OK'
      }
    ];

    const results = engine.getAuditResults(mockResults);
    expect(results.length).toBe(1);
    expect(results[0].passed).toBe(true);
    expect(results[0].rule).toBe('overall-grade');
    expect(results[0].message).toContain('A+ meets the minimum requirement of A');
  });

  it('should return fail result for grade not meeting requirement', () => {
    const mockResults: TestSSLScanItem[] = [
      {
        id: 'overall_grade',
        finding: 'B',
        severity: 'MEDIUM'
      }
    ];

    const results = engine.getAuditResults(mockResults);
    expect(results.length).toBe(1);
    expect(results[0].passed).toBe(false);
    expect(results[0].rule).toBe('overall-grade');
    expect(results[0].message).toContain('does not meet minimum requirement');
  });

  it('should include IP in TLS version messages', () => {
    const mockResults: TestSSLScanItem[] = [
      {
        id: 'TLS1',
        ip: 'www.example.org/172.67.135.178',
        port: '443',
        severity: 'LOW',
        finding: 'offered (deprecated)'
      },
      {
        id: 'TLS1',
        ip: 'www.example.org/104.21.7.36',
        port: '443',
        severity: 'LOW',
        finding: 'offered (deprecated)'
      }
    ];

    const results = engine.getAuditResults(mockResults);
    expect(results.length).toBe(2);
    expect(results[0].passed).toBe(false);
    expect(results[0].message).toContain('[www.example.org/172.67.135.178]');
    expect(results[1].passed).toBe(false);
    expect(results[1].message).toContain('[www.example.org/104.21.7.36]');
  });

  it('should return pass result for secure TLS versions', () => {
    const mockResults: TestSSLScanItem[] = [
      {
        id: 'TLS1_2',
        ip: 'www.example.org/172.67.135.178',
        port: '443',
        severity: 'OK',
        finding: 'offered'
      },
      {
        id: 'TLS1_3',
        ip: 'www.example.org/172.67.135.178',
        port: '443',
        severity: 'OK',
        finding: 'offered'
      }
    ];

    const results = engine.getAuditResults(mockResults);
    expect(results.length).toBe(2);
    expect(results[0].passed).toBe(true);
    expect(results[0].message).toContain('TLS1.2 meets the minimum requirement');
    expect(results[1].passed).toBe(true);
    expect(results[1].message).toContain('TLS1.3 meets the minimum requirement');
  });

  it('should return pass result for blocked ciphers not offered', () => {
    const mockResults: TestSSLScanItem[] = [
      {
        id: 'cipherlist_3DES_IDEA',
        ip: 'www.example.org/172.67.135.178',
        port: '443',
        severity: 'MEDIUM',
        finding: 'not offered'
      },
      {
        id: 'cipherlist_RC4',
        ip: 'www.example.org/172.67.135.178',
        port: '443',
        severity: 'OK',
        finding: 'not offered'
      }
    ];

    const results = engine.getAuditResults(mockResults);
    expect(results.length).toBe(2);
    expect(results[0].passed).toBe(true);
    expect(results[0].message).toContain('3DES_IDEA is not offered');
    expect(results[1].passed).toBe(true);
    expect(results[1].message).toContain('RC4 is not offered');
  });

  it('should include IP in cipher messages', () => {
    const mockResults: TestSSLScanItem[] = [
      {
        id: 'cipherlist_RC4',
        ip: 'www.example.org/172.67.135.178',
        port: '443',
        severity: 'OK',
        finding: 'not offered'
      }
    ];

    const results = engine.getAuditResults(mockResults);
    expect(results.length).toBe(1);
    expect(results[0].message).toContain('[www.example.org/172.67.135.178]');
  });
});
