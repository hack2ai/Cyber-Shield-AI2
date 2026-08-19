import { describe, expect, it } from 'vitest';
import {
  assertSafeResolvedAddresses,
  classifyTarget,
  isBlockedHostname,
  isIPv4,
  isIPv6,
  isPrivateOrReservedIPv4,
  isPrivateOrReservedIPv6,
} from './server.js';

describe('IP classification', () => {
  it('recognizes dotted-decimal IPv4 syntax', () => {
    expect(isIPv4('203.0.113.10')).toBe(true);
    expect(isIPv4('203.0.113')).toBe(false);
  });

  it('blocks private and reserved IPv4 ranges', () => {
    expect(isPrivateOrReservedIPv4('10.10.10.10')).toBe(true);
    expect(isPrivateOrReservedIPv4('172.16.0.1')).toBe(true);
    expect(isPrivateOrReservedIPv4('192.168.1.1')).toBe(true);
    expect(isPrivateOrReservedIPv4('127.0.0.1')).toBe(true);
    expect(isPrivateOrReservedIPv4('169.254.1.1')).toBe(true);
    expect(isPrivateOrReservedIPv4('203.0.113.10')).toBe(true);
  });

  it('blocks IPv6 loopback, link-local, unique-local and documentation space', () => {
    expect(isIPv6('::1')).toBe(true);
    expect(isPrivateOrReservedIPv6('::1')).toBe(true);
    expect(isPrivateOrReservedIPv6('fe80::1')).toBe(true);
    expect(isPrivateOrReservedIPv6('fd00::1')).toBe(true);
    expect(isPrivateOrReservedIPv6('2001:db8::10')).toBe(true);
  });

  it('inherits IPv4 blocking policy for IPv4-mapped IPv6 literals', () => {
    expect(isPrivateOrReservedIPv6('::ffff:192.168.1.10')).toBe(true);
    expect(isPrivateOrReservedIPv6('::ffff:8.8.8.8')).toBe(false);
  });

  it('rejects private-only and mixed public/private DNS answers', () => {
    expect(() => assertSafeResolvedAddresses(['fd00::1'])).toThrow(/Blocked internal or reserved destination/);
    expect(() => assertSafeResolvedAddresses(['8.8.8.8', 'fd00::1'])).toThrow(/Blocked internal or reserved destination/);
    expect(assertSafeResolvedAddresses(['8.8.8.8', '2001:4860:4860::8888'])).toEqual([
      '8.8.8.8',
      '2001:4860:4860::8888',
    ]);
  });
});

describe('hostname and target classification', () => {
  it('blocks local hostnames', () => {
    expect(isBlockedHostname('localhost')).toBe(true);
    expect(isBlockedHostname('service.localhost')).toBe(true);
    expect(isBlockedHostname('printer.local')).toBe(true);
    expect(isBlockedHostname('example.com')).toBe(false);
  });

  it('classifies IPv4, IPv6 and URLs consistently', () => {
    expect(classifyTarget('8.8.8.8')).toMatchObject({ type: 'ip', hostname: '8.8.8.8' });
    expect(classifyTarget('2001:4860:4860::8888')).toMatchObject({ type: 'ip', hostname: '2001:4860:4860::8888' });
    expect(classifyTarget('https://example.com/login')).toMatchObject({ type: 'url', hostname: 'example.com' });
  });
});
