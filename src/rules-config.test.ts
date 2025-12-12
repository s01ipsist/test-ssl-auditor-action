import { loadRulesConfig, DEFAULT_RULES } from '../src/rules-config';
import { writeFile, unlink } from 'fs/promises';
import { join } from 'path';

describe('loadRulesConfig', () => {
  const testConfigPath = join(__dirname, 'test-config.json');

  afterEach(async () => {
    try {
      await unlink(testConfigPath);
    } catch {
      // File may not exist
    }
  });

  it('should return default rules when config file does not exist', async () => {
    const config = await loadRulesConfig('/nonexistent/path.json');
    expect(config).toEqual(DEFAULT_RULES);
  });

  it('should load and parse valid config file', async () => {
    const testConfig = {
      rules: {
        minTlsVersion: '1.3',
        blockedCiphers: ['RC4']
      }
    };

    await writeFile(testConfigPath, JSON.stringify(testConfig));
    const config = await loadRulesConfig(testConfigPath);

    expect(config.rules.minTlsVersion).toBe('1.3');
    expect(config.rules.blockedCiphers).toEqual(['RC4']);
  });

  it('should merge with default rules', async () => {
    const testConfig = {
      rules: {
        minTlsVersion: '1.3'
      }
    };

    await writeFile(testConfigPath, JSON.stringify(testConfig));
    const config = await loadRulesConfig(testConfigPath);

    expect(config.rules.minTlsVersion).toBe('1.3');
    expect(config.rules.requireForwardSecrecy).toBe(
      DEFAULT_RULES.rules.requireForwardSecrecy
    );
  });
});
