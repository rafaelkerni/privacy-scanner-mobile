import { OuiClassification, OuiResult, DiscoveredHost } from './types';
import { TIER1_OUIS, TIER2_OUIS } from '../data/oui-database';
import {
  SAFE_MANUFACTURERS, IOT_CHIPSETS, GENERIC_CHIPSETS, CAMERA_MFR_KEYWORDS,
} from '../data/keywords';

export function macToOui(mac: string): string {
  return mac.toUpperCase().replace(/[:\-\.]/g, '').substring(0, 6);
}

export function isMacRandomized(mac: string): boolean {
  const cleaned = mac.replace(/[:\-\.]/g, '');
  if (cleaned.length < 2) return false;
  const firstByte = parseInt(cleaned.substring(0, 2), 16);
  return (firstByte & 0x02) !== 0;
}

function matchesAny(value: string, patterns: readonly string[]): boolean {
  const lower = value.toLowerCase();
  return patterns.some(p => lower.includes(p.toLowerCase()));
}

export function lookupOui(host: DiscoveredHost): OuiResult {
  const { ip, mac, oui } = host;
  const randomized = isMacRandomized(mac);

  if (!randomized && oui in TIER1_OUIS) {
    return {
      ip, mac, oui,
      manufacturer: TIER1_OUIS[oui],
      classification: 'TIER1_CAMERA',
    };
  }

  if (!randomized && oui in TIER2_OUIS) {
    return {
      ip, mac, oui,
      manufacturer: TIER2_OUIS[oui],
      classification: 'TIER2_CAMERA',
    };
  }

  if (randomized) {
    return {
      ip, mac, oui,
      manufacturer: '(MAC randomizado)',
      classification: 'MAC_RANDOMIZED',
    };
  }

  // No match in our embedded database — classify as unknown
  // In production, you could add a larger OUI database as a JSON asset
  return {
    ip, mac, oui,
    manufacturer: '',
    classification: 'UNKNOWN',
  };
}

export function classifyManufacturer(manufacturer: string): OuiClassification {
  if (!manufacturer) return 'UNKNOWN';
  if (matchesAny(manufacturer, CAMERA_MFR_KEYWORDS)) return 'CAMERA_KEYWORD';
  if (matchesAny(manufacturer, IOT_CHIPSETS)) return 'IOT_CHIPSET';
  if (matchesAny(manufacturer, SAFE_MANUFACTURERS)) return 'KNOWN_SAFE';
  if (matchesAny(manufacturer, GENERIC_CHIPSETS)) return 'GENERIC_CHIPSET';
  return 'KNOWN_OTHER';
}

export function analyzeHosts(hosts: DiscoveredHost[]): OuiResult[] {
  return hosts.map(lookupOui);
}
