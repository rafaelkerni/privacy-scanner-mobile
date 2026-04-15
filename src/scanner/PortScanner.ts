import { NetworkScanner } from '../../modules/network-scanner';
import { PortResult } from './types';
import { CAMERA_PORTS } from '../data/camera-ports';

const PORT_SCAN_TIMEOUT = 2500;

export async function scanPorts(
  hosts: string[],
  onProgress?: (msg: string) => void,
): Promise<PortResult[]> {
  const allResults: PortResult[] = [];

  for (let i = 0; i < hosts.length; i++) {
    const host = hosts[i];
    onProgress?.(`Escaneando ${host} (${i + 1}/${hosts.length})...`);

    try {
      const openPorts = await NetworkScanner.scanPorts(
        host,
        [...CAMERA_PORTS],
        PORT_SCAN_TIMEOUT,
      );

      for (const result of openPorts) {
        allResults.push({
          ip: host,
          port: result.port,
          open: true,
          banner: result.banner,
        });
      }
    } catch {
      // Host unreachable or scan failed — skip
    }
  }

  return allResults;
}
