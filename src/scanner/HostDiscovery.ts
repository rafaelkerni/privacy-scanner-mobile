import { NetworkScanner } from '../../modules/network-scanner';
import { DiscoveredHost, NetworkInfo } from './types';
import { macToOui } from './OuiLookup';

export async function getNetworkInfo(): Promise<NetworkInfo> {
  const wifi = await NetworkScanner.getWifiInfo();

  // Calculate subnet CIDR from local IP (assume /24 for typical home networks)
  const parts = wifi.localIp.split('.');
  const subnet = parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}.0/24` : '';

  return {
    localIp: wifi.localIp,
    gateway: wifi.gateway,
    netmask: wifi.netmask,
    ssid: wifi.ssid,
    bssid: wifi.bssid,
    subnet,
  };
}

export async function discoverHosts(
  networkInfo: NetworkInfo,
  onProgress?: (msg: string) => void,
): Promise<DiscoveredHost[]> {
  const seen = new Map<string, DiscoveredHost>();
  const localIp = networkInfo.localIp;
  const gateway = networkInfo.gateway;

  // Extract base IP from local IP
  const parts = localIp.split('.');
  if (parts.length !== 4) return [];
  const baseIp = `${parts[0]}.${parts[1]}.${parts[2]}`;

  // Step 1: Read existing ARP table (already populated entries)
  onProgress?.('Lendo tabela ARP...');
  try {
    const arpEntries = await NetworkScanner.readArpTable();
    for (const entry of arpEntries) {
      if (entry.ip === localIp) continue;
      const oui = macToOui(entry.mac);
      seen.set(entry.ip, { ip: entry.ip, mac: entry.mac, oui });
    }
  } catch {}

  // Step 2: Discover live hosts via TCP/ICMP sweep to populate ARP cache
  onProgress?.(`Escaneando ${baseIp}.1-254...`);
  try {
    const liveHosts = await NetworkScanner.discoverHosts(baseIp, 1, 254, 80, 400);
    // Also try port 7 (echo) for hosts that don't respond on 80
    const additionalHosts = await NetworkScanner.discoverHosts(baseIp, 1, 254, 7, 300);
    const allLive = new Set([...liveHosts, ...additionalHosts]);
    onProgress?.(`${allLive.size} hosts responderam`);
  } catch {}

  // Step 3: Read ARP table again (now populated from the sweep)
  onProgress?.('Relendo tabela ARP...');
  try {
    const arpEntries = await NetworkScanner.readArpTable();
    for (const entry of arpEntries) {
      if (entry.ip === localIp) continue;
      if (seen.has(entry.ip)) continue;
      const oui = macToOui(entry.mac);
      seen.set(entry.ip, { ip: entry.ip, mac: entry.mac, oui });
    }
  } catch {}

  // Filter out gateway if desired (keep it, mark it later)
  const hosts = Array.from(seen.values());

  // Sort by IP for consistent ordering
  hosts.sort((a, b) => {
    const aParts = a.ip.split('.').map(Number);
    const bParts = b.ip.split('.').map(Number);
    for (let i = 0; i < 4; i++) {
      if (aParts[i] !== bParts[i]) return aParts[i] - bParts[i];
    }
    return 0;
  });

  return hosts;
}
