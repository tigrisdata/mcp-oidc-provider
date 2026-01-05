import { describe, it, expect } from 'vitest';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Helper to run the CLI
function runCli(args: string[] = []): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    const cliPath = join(__dirname, 'generate-jwks.ts');
    const proc = spawn('npx', ['tsx', cliPath, ...args], {
      cwd: join(__dirname, '..', '..'),
      env: { ...process.env },
    });

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    proc.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    proc.on('close', (code) => {
      resolve({ stdout, stderr, code: code ?? 0 });
    });
  });
}

describe('generate-jwks CLI', () => {
  it('should generate valid JWKS JSON', async () => {
    const { stdout, code } = await runCli();

    expect(code).toBe(0);
    const jwks = JSON.parse(stdout.trim());
    expect(jwks.keys).toBeDefined();
    expect(Array.isArray(jwks.keys)).toBe(true);
    expect(jwks.keys.length).toBeGreaterThan(0);
  }, 30000);

  it('should generate pretty-printed JWKS with --pretty flag', async () => {
    const { stdout, code } = await runCli(['--pretty']);

    expect(code).toBe(0);
    // Pretty output should have multiple lines
    expect(stdout.split('\n').length).toBeGreaterThan(1);
    const jwks = JSON.parse(stdout);
    expect(jwks.keys).toBeDefined();
  }, 30000);

  it('should generate pretty-printed JWKS with -p flag', async () => {
    const { stdout, code } = await runCli(['-p']);

    expect(code).toBe(0);
    expect(stdout.split('\n').length).toBeGreaterThan(1);
  }, 30000);

  it('should show help with --help flag', async () => {
    const { stdout, code } = await runCli(['--help']);

    expect(code).toBe(0);
    expect(stdout).toContain('Usage:');
    expect(stdout).toContain('Options:');
    expect(stdout).toContain('--pretty');
    expect(stdout).toContain('--help');
  }, 30000);

  it('should show help with -h flag', async () => {
    const { stdout, code } = await runCli(['-h']);

    expect(code).toBe(0);
    expect(stdout).toContain('Usage:');
  }, 30000);

  it('should generate RSA keys in JWKS', async () => {
    const { stdout, code } = await runCli();

    expect(code).toBe(0);
    const jwks = JSON.parse(stdout.trim());
    const rsaKey = jwks.keys.find((k: { kty: string }) => k.kty === 'RSA');
    expect(rsaKey).toBeDefined();
    expect(rsaKey.kty).toBe('RSA');
    expect(rsaKey.use).toBe('sig');
    expect(rsaKey.kid).toBeDefined();
  }, 30000);
});
