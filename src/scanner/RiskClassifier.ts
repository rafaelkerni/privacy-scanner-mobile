import {
  OuiResult, PortResult, ServiceResult, HttpFinding, RtspFinding,
  DeviceClassification, RiskCounts, RiskLevel,
} from './types';
import { RTSP_PORTS, HTTP_PORTS, VENDOR_PORTS } from '../data/camera-ports';
import { MDNS_CAMERA_SERVICES } from '../data/keywords';

export function classify(
  ouiResults: OuiResult[],
  portResults: PortResult[],
  serviceResults: ServiceResult[],
  httpFindings: HttpFinding[],
  rtspFindings: RtspFinding[],
): { classifications: DeviceClassification[]; counts: RiskCounts } {
  // Build lookup maps
  const ipPorts = new Map<string, Set<number>>();
  for (const pr of portResults) {
    if (!ipPorts.has(pr.ip)) ipPorts.set(pr.ip, new Set());
    ipPorts.get(pr.ip)!.add(pr.port);
  }

  const ipHttpTypes = new Map<string, Set<string>>();
  for (const hf of httpFindings) {
    if (!ipHttpTypes.has(hf.ip)) ipHttpTypes.set(hf.ip, new Set());
    ipHttpTypes.get(hf.ip)!.add(hf.type);
  }

  const ipRtspConfirmed = new Set<string>();
  for (const rf of rtspFindings) {
    if (rf.confirmed) ipRtspConfirmed.add(rf.ip);
  }

  const ipServices = new Map<string, Set<string>>();
  for (const sr of serviceResults) {
    if (!ipServices.has(sr.ip)) ipServices.set(sr.ip, new Set());
    ipServices.get(sr.ip)!.add(sr.serviceType);
  }

  const classifications: DeviceClassification[] = [];
  const counts: RiskCounts = { CRITICAL: 0, HIGH: 0, MODERATE: 0, LOW: 0, INFO: 0 };

  for (const device of ouiResults) {
    const { ip, mac, manufacturer, classification } = device;
    const openPorts = ipPorts.get(ip) ?? new Set<number>();
    const openPortsStr = Array.from(openPorts).sort((a, b) => a - b).join(',');
    const deepTypes = ipHttpTypes.get(ip) ?? new Set<string>();
    const svcTypes = ipServices.get(ip) ?? new Set<string>();

    const hasRtsp = [...openPorts].some(p => RTSP_PORTS.has(p));
    const hasHttp = [...openPorts].some(p => HTTP_PORTS.has(p));
    const hasVendorPort = [...openPorts].some(p => VENDOR_PORTS.has(p));
    const hasCameraWebui = deepTypes.has('CAMERA_WEBUI') || deepTypes.has('CAMERA_TITLE');
    const hasCameraHeader = deepTypes.has('CAMERA_HEADER');
    const hasRtspConfirmed = ipRtspConfirmed.has(ip);
    const hasMdnsCamera = [...svcTypes].some(s => {
      const lower = s.toLowerCase();
      return MDNS_CAMERA_SERVICES.some(cs => lower.includes(cs.replace(/\.$/, '')));
    });

    let risk: RiskLevel = 'INFO';
    let deviceType = 'Unknown';
    let evidence = '';
    let recommendation = '';

    // --- CRITICAL ---
    if (classification === 'TIER1_CAMERA' && (hasRtsp || hasVendorPort)) {
      risk = 'CRITICAL';
      deviceType = 'Surveillance Camera (confirmed)';
      evidence = `Surveillance manufacturer (${manufacturer}) + streaming/control ports (${openPortsStr})`;
      recommendation = 'LIKELY ACTIVE CAMERA. Photograph device. Contact Airbnb support immediately.';
    } else if (hasRtspConfirmed) {
      risk = 'CRITICAL';
      deviceType = 'RTSP Streaming Device (confirmed)';
      evidence = 'Active RTSP streaming service detected';
      recommendation = 'CONFIRMED VIDEO STREAMING. Locate and photograph the device.';
    } else if (hasCameraWebui || hasCameraHeader) {
      risk = 'CRITICAL';
      deviceType = 'Camera Web Interface (confirmed)';
      evidence = 'Camera web UI or server header detected';
      recommendation = 'CAMERA WEB INTERFACE FOUND. Photograph evidence.';
    } else if (hasMdnsCamera) {
      risk = 'CRITICAL';
      deviceType = 'Camera Service (mDNS)';
      evidence = 'Camera/RTSP service advertising via mDNS';
      recommendation = 'CAMERA ANNOUNCING ON NETWORK. Locate device.';
    }

    // --- HIGH ---
    else if (classification === 'TIER1_CAMERA') {
      risk = 'HIGH';
      deviceType = 'Surveillance Equipment';
      evidence = `Known surveillance manufacturer: ${manufacturer}`;
      recommendation = 'Surveillance manufacturer device on network. Try to locate it physically.';
    } else if (classification === 'TIER2_CAMERA') {
      risk = 'HIGH';
      deviceType = 'Consumer Camera';
      evidence = `Known camera brand: ${manufacturer}`;
      recommendation = 'Consumer camera brand detected. Check if disclosed in listing.';
    } else if (classification === 'CAMERA_KEYWORD') {
      risk = 'HIGH';
      deviceType = 'Camera-Related Device';
      evidence = `Manufacturer suggests camera/surveillance: ${manufacturer}`;
      recommendation = 'Camera-related manufacturer. Investigate further.';
    } else if (classification === 'UNKNOWN' && hasRtsp) {
      risk = 'HIGH';
      deviceType = 'Unknown Device with RTSP';
      evidence = 'Unknown manufacturer + RTSP port open';
      recommendation = 'Unknown device with video streaming port. Investigate immediately.';
    } else if (classification === 'UNKNOWN' && hasVendorPort) {
      risk = 'HIGH';
      deviceType = 'Unknown Device with Camera Port';
      evidence = 'Unknown manufacturer + vendor camera port open';
      recommendation = 'Unknown device with camera-specific port. Investigate.';
    } else if (classification === 'MAC_RANDOMIZED' && (hasRtsp || hasVendorPort)) {
      risk = 'HIGH';
      deviceType = 'Randomized MAC (suspicious ports)';
      evidence = `Randomized MAC + camera-related ports (${openPortsStr})`;
      recommendation = 'Device hiding identity with camera ports open. Investigate immediately.';
    }

    // --- MODERATE ---
    else if (classification === 'MAC_RANDOMIZED' && hasHttp) {
      risk = 'MODERATE';
      deviceType = 'Randomized MAC (web interface)';
      evidence = 'Randomized MAC address + HTTP service';
      recommendation = 'Device with hidden identity and web server. Likely a phone, but verify.';
    } else if (classification === 'IOT_CHIPSET' && (hasRtsp || hasVendorPort)) {
      risk = 'MODERATE';
      deviceType = 'IoT Device (suspicious ports)';
      evidence = `IoT chipset (${manufacturer}) + camera ports (${openPortsStr})`;
      recommendation = 'IoT device with suspicious ports. Could be a camera.';
    } else if (classification === 'IOT_CHIPSET' && hasHttp) {
      risk = 'MODERATE';
      deviceType = 'IoT Device (web interface)';
      evidence = `IoT chipset (${manufacturer}) + HTTP service`;
      recommendation = 'IoT device with web interface. Check if camera.';
    } else if (classification === 'UNKNOWN' && hasHttp) {
      risk = 'MODERATE';
      deviceType = 'Unknown Device (web interface)';
      evidence = `Unknown manufacturer + HTTP service (${openPortsStr})`;
      recommendation = 'Unidentified device with web server. Try accessing its web interface.';
    } else if (classification === 'GENERIC_CHIPSET' && (hasRtsp || hasVendorPort)) {
      risk = 'MODERATE';
      deviceType = 'Generic Chipset (suspicious ports)';
      evidence = `Generic chipset (${manufacturer}) + camera ports (${openPortsStr})`;
      recommendation = 'Generic device with camera-specific ports. Investigate.';
    } else if (classification === 'UNKNOWN') {
      risk = 'MODERATE';
      deviceType = 'Unidentified Device';
      evidence = `Unknown manufacturer, MAC: ${mac}`;
      recommendation = 'Cannot identify this device. Try to locate it physically.';
    }

    // --- LOW ---
    else if (classification === 'MAC_RANDOMIZED') {
      risk = 'LOW';
      deviceType = 'Randomized MAC (likely phone/laptop)';
      evidence = 'MAC randomization — typically modern phone, tablet, or laptop';
      recommendation = 'Likely a personal device using privacy MAC.';
    } else if (classification === 'IOT_CHIPSET') {
      risk = 'LOW';
      deviceType = 'IoT Device';
      evidence = `IoT chipset (${manufacturer}), no camera ports`;
      recommendation = 'Likely a smart home device (plug, sensor, etc.)';
    } else if (classification === 'GENERIC_CHIPSET') {
      risk = 'LOW';
      deviceType = 'Network Device';
      evidence = `Generic chipset (${manufacturer})`;
      recommendation = 'Likely a router, switch, or network adapter';
    }

    // --- INFO ---
    else if (classification === 'KNOWN_SAFE' || classification === 'KNOWN_OTHER') {
      risk = 'INFO';
      deviceType = 'Known Device';
      evidence = `Identified manufacturer: ${manufacturer}`;
      recommendation = 'Known device type, no camera indicators';
    }

    counts[risk]++;
    classifications.push({
      risk, ip, mac, manufacturer,
      deviceType, openPorts: openPortsStr,
      evidence, recommendation,
    });
  }

  // Sort by risk severity
  const riskOrder: Record<RiskLevel, number> = {
    CRITICAL: 0, HIGH: 1, MODERATE: 2, LOW: 3, INFO: 4,
  };
  classifications.sort((a, b) => riskOrder[a.risk] - riskOrder[b.risk]);

  return { classifications, counts };
}
