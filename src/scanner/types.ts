export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW' | 'INFO';

export type OuiClassification =
  | 'TIER1_CAMERA'
  | 'TIER2_CAMERA'
  | 'CAMERA_KEYWORD'
  | 'IOT_CHIPSET'
  | 'GENERIC_CHIPSET'
  | 'KNOWN_SAFE'
  | 'KNOWN_OTHER'
  | 'MAC_RANDOMIZED'
  | 'UNKNOWN';

export interface DiscoveredHost {
  ip: string;
  mac: string;
  oui: string;
}

export interface OuiResult {
  ip: string;
  mac: string;
  oui: string;
  manufacturer: string;
  classification: OuiClassification;
}

export interface PortResult {
  ip: string;
  port: number;
  open: boolean;
  banner: string;
}

export interface ServiceResult {
  ip: string;
  method: 'mDNS' | 'UPnP';
  serviceType: string;
  name: string;
  txt: string;
}

export interface HttpFinding {
  ip: string;
  port: number;
  type: 'CAMERA_HEADER' | 'CAMERA_WEBUI' | 'CAMERA_TITLE' | 'POSSIBLE_CAMERA';
  detail: string;
}

export interface RtspFinding {
  ip: string;
  port: number;
  confirmed: boolean;
  banner: string;
}

export interface DeviceClassification {
  risk: RiskLevel;
  ip: string;
  mac: string;
  manufacturer: string;
  deviceType: string;
  openPorts: string;
  evidence: string;
  recommendation: string;
}

export interface RiskCounts {
  CRITICAL: number;
  HIGH: number;
  MODERATE: number;
  LOW: number;
  INFO: number;
}

export type ScanPhase =
  | 'idle'
  | 'network_info'
  | 'host_discovery'
  | 'oui_analysis'
  | 'port_scan'
  | 'service_discovery'
  | 'http_inspection'
  | 'rtsp_probe'
  | 'classification'
  | 'done'
  | 'error';

export interface ScanProgress {
  phase: ScanPhase;
  phaseIndex: number;
  totalPhases: number;
  message: string;
  detail?: string;
}

export interface NetworkInfo {
  localIp: string;
  gateway: string;
  netmask: string;
  ssid: string;
  bssid: string;
  subnet: string;
}

export interface ScanResults {
  networkInfo: NetworkInfo;
  hosts: DiscoveredHost[];
  ouiResults: OuiResult[];
  portResults: PortResult[];
  serviceResults: ServiceResult[];
  httpFindings: HttpFinding[];
  rtspFindings: RtspFinding[];
  classifications: DeviceClassification[];
  counts: RiskCounts;
  duration: number;
  timestamp: string;
  quickMode: boolean;
}
