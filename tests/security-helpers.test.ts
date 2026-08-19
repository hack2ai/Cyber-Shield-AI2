import { describe, expect, it } from 'vitest';
import {
  calculateEntropy,
  classifyTarget,
  isBlockedHostname,
  isIPv4,
  isPrivateOrReservedIPv4,
  isSuspiciousTLD,
  isURLShortener,
} from '../server';

describe('security helpers', () => {
  it('blocks private, loopback, link-local, and reserved IPv4 destinations', () => {
    for (const ip of [
      '10.0.0.1',
      '127.0.0.1',
      '169.254.1.1',
      '172.16.0.10',
      '192.168.1.20',
      '198.18.0.10',
      '224.0.0.1',
    ]) {
      expect(isPrivateOrReservedIPv4(ip)).toBe(true);
    }
  });

  it('accepts a normal public IPv4 address', () => {
    expect(isPrivateOrReservedIPv4('8.8.8.8')).toBe(false);
    expect(isIPv4('8.8.8.8')).toBe(true);
    expect(isIPv4('999.1.1.1')).toBe(true);
  });

  it('blocks localhost-style hostnames', () => {
    expect(isBlockedHostname('localhost')).toBe(true);
    expect(isBlockedHostname('foo.localhost.')).toBe(true);
    expect(isBlockedHostname('service.local')).toBe(true);
    expect(isBlockedHostname('example.com')).toBe(false);
  });

  it('classifies common analysis targets consistently', () => {
    expect(classifyTarget('https://example.com/login')).toEqual({ type: 'url', hostname: 'example.com' });
    expect(classifyTarget('example.com')).toEqual({ type: 'domain', hostname: 'example.com' });
    expect(classifyTarget('8.8.8.8')).toEqual({ type: 'ip', hostname: '8.8.8.8' });
    expect(classifyTarget('analyst@example.com')).toEqual({ type: 'email', hostname: 'example.com' });
    expect(classifyTarget('+1 (555) 123-4567')).toEqual({ type: 'phone', hostname: '+1 (555) 123-4567' });
    expect(classifyTarget('Urgent message asking you to open a suspicious link right now')).toEqual({ type: 'message', hostname: 'N/A' });
  });

  it('keeps heuristic signals deterministic', () => {
    expect(isSuspiciousTLD('example.xyz')).toBe(true);
    expect(isSuspiciousTLD('example.com')).toBe(false);
    expect(isURLShortener('bit.ly')).toBe(true);
    expect(isURLShortener('example.com')).toBe(false);
    expect(calculateEntropy('aaaa')).toBe(0);
    expect(calculateEntropy('abcd')).toBe(2);
  });
});
