import { NetworkScanner } from '../../modules/network-scanner';
import { RtspFinding } from './types';

export async function probeRtsp(
  targets: Array<{ ip: string; port: number }>,
  onProgress?: (msg: string) => void,
): Promise<RtspFinding[]> {
  const findings: RtspFinding[] = [];

  for (const { ip, port } of targets) {
    onProgress?.(`RTSP ${ip}:${port}`);

    try {
      const result = await NetworkScanner.probeRtsp(ip, port);
      const response = result.response ?? '';
      const isRtsp = response.includes('RTSP/1.0') ||
                     response.toLowerCase().includes('rtsp') ||
                     response.includes('OPTIONS') ||
                     response.includes('DESCRIBE');

      findings.push({
        ip,
        port,
        confirmed: result.success && isRtsp,
        banner: response.substring(0, 200),
      });
    } catch {
      findings.push({ ip, port, confirmed: false, banner: '' });
    }
  }

  return findings;
}
