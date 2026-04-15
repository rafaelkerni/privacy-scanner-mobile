import { NetworkScanner } from '../../modules/network-scanner';
import { ServiceResult } from './types';
import { MDNS_CAMERA_SERVICES } from '../data/keywords';

const MDNS_SERVICE_TYPES = [
  '_rtsp._tcp',
  '_camera._tcp',
  '_nvr._tcp',
  '_onvif._tcp',
  '_http._tcp',
];

export async function discoverServices(
  onProgress?: (msg: string) => void,
): Promise<ServiceResult[]> {
  const results: ServiceResult[] = [];

  onProgress?.('Buscando serviços mDNS...');

  try {
    const services = await NetworkScanner.discoverMdnsServices(
      MDNS_SERVICE_TYPES,
      8000,
    );

    for (const svc of services) {
      results.push({
        ip: svc.ip,
        method: 'mDNS',
        serviceType: svc.serviceType,
        name: svc.name,
        txt: `port:${svc.port}`,
      });
    }

    onProgress?.(`${results.length} serviços mDNS encontrados`);
  } catch {
    onProgress?.('mDNS não disponível');
  }

  return results;
}

export function isCameraService(serviceType: string): boolean {
  const lower = serviceType.toLowerCase();
  return MDNS_CAMERA_SERVICES.some(s => lower.includes(s.replace(/\.$/, '')));
}
