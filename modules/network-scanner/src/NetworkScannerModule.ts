import { requireNativeModule } from 'expo-modules-core';

interface ArpEntry {
  ip: string;
  mac: string;
}

interface WifiInfo {
  gateway: string;
  localIp: string;
  netmask: string;
  ssid: string;
  bssid: string;
}

interface PortScanResult {
  port: number;
  open: boolean;
  banner: string;
}

interface RtspProbeResult {
  success: boolean;
  response: string;
}

interface MdnsService {
  name: string;
  serviceType: string;
  ip: string;
  port: string;
}

interface NetworkScannerInterface {
  readArpTable(): Promise<ArpEntry[]>;
  getWifiInfo(): Promise<WifiInfo>;
  scanPorts(host: string, ports: number[], timeoutMs: number): Promise<PortScanResult[]>;
  probeRtsp(host: string, port: number): Promise<RtspProbeResult>;
  discoverHosts(baseIp: string, startHost: number, endHost: number, port: number, timeoutMs: number): Promise<string[]>;
  pingHost(host: string, timeoutMs: number): Promise<boolean>;
  discoverMdnsServices(serviceTypes: string[], timeoutMs: number): Promise<MdnsService[]>;
}

const NetworkScanner: NetworkScannerInterface = requireNativeModule('NetworkScanner');

export default NetworkScanner;
