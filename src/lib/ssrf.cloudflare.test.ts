import dns from 'node:dns/promises';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { isBlockedByDNS } from './ssrf';

vi.mock('node:dns/promises', () => ({
  default: { resolve4: vi.fn(), resolve6: vi.fn() },
}));

beforeEach(() => vi.resetAllMocks());

describe('DNS SSRF guard on Cloudflare Workers', () => {
  it('allows a resolved public IPv4 address', async () => {
    vi.mocked(dns.resolve4).mockResolvedValue(['1.1.1.1']);
    vi.mocked(dns.resolve6).mockRejectedValue(new Error('ENODATA'));
    expect(await isBlockedByDNS('https://example.com')).toBe(false);
  });

  it('rejects a private address on either DNS family', async () => {
    vi.mocked(dns.resolve4).mockResolvedValue(['192.168.1.5']);
    vi.mocked(dns.resolve6).mockResolvedValue(['2606:4700::1111']);
    expect(await isBlockedByDNS('https://example.com')).toBe(true);
  });

  it('fails closed when both DNS families fail', async () => {
    vi.mocked(dns.resolve4).mockRejectedValue(new Error('ENOTFOUND'));
    vi.mocked(dns.resolve6).mockRejectedValue(new Error('ENOTFOUND'));
    expect(await isBlockedByDNS('https://invalid.example')).toBe(true);
  });
});
