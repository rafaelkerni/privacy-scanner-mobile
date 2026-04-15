import { ScanProgress, ScanResults, NetworkInfo } from './types';
import { HTTP_PORTS, RTSP_PORTS } from '../data/camera-ports';
import { getNetworkInfo, discoverHosts } from './HostDiscovery';
import { analyzeHosts } from './OuiLookup';
import { scanPorts } from './PortScanner';
import { discoverServices } from './ServiceDiscovery';
import { inspectHttpServices } from './HttpInspector';
import { probeRtsp } from './RtspProber';
import { classify } from './RiskClassifier';

export type ProgressCallback = (progress: ScanProgress) => void;

export async function runScan(
  quickMode: boolean,
  onProgress: ProgressCallback,
): Promise<ScanResults> {
  const startTime = Date.now();
  const totalPhases = quickMode ? 5 : 7;
  let phaseIndex = 0;

  const report = (phase: ScanProgress['phase'], message: string, detail?: string) => {
    onProgress({ phase, phaseIndex, totalPhases, message, detail });
  };

  // Phase 1: Network Info
  report('network_info', 'Detectando rede...', '');
  phaseIndex++;
  let networkInfo: NetworkInfo;
  try {
    networkInfo = await getNetworkInfo();
    report('network_info', `Rede: ${networkInfo.ssid}`, `IP: ${networkInfo.localIp}`);
  } catch (err) {
    report('error', 'Falha ao detectar rede', String(err));
    throw new Error('Não foi possível detectar a rede. Verifique a conexão WiFi.');
  }

  // Phase 2: Host Discovery
  report('host_discovery', 'Descobrindo dispositivos na rede...', networkInfo.subnet);
  phaseIndex++;
  const hosts = await discoverHosts(networkInfo, (msg) => {
    report('host_discovery', msg);
  });
  report('host_discovery', `${hosts.length} dispositivos encontrados`);

  if (hosts.length === 0) {
    // Return empty results
    return buildEmptyResults(networkInfo, quickMode, startTime);
  }

  // Phase 3: OUI Analysis
  report('oui_analysis', 'Identificando fabricantes...', `${hosts.length} dispositivos`);
  phaseIndex++;
  const ouiResults = analyzeHosts(hosts);
  const cameraCount = ouiResults.filter(
    r => r.classification === 'TIER1_CAMERA' || r.classification === 'TIER2_CAMERA'
  ).length;
  report('oui_analysis', `${cameraCount} fabricantes de câmera identificados`);

  // Phase 4: Port Scanning
  report('port_scan', 'Escaneando portas de câmera...', `${hosts.length} alvos`);
  phaseIndex++;
  const hostIps = ouiResults.map(r => r.ip);
  const portResults = await scanPorts(hostIps, (msg) => {
    report('port_scan', msg);
  });
  report('port_scan', `${portResults.length} portas abertas encontradas`);

  // Phase 5: Service Discovery (mDNS) — skipped in quick mode
  let serviceResults = quickMode ? [] : await (async () => {
    report('service_discovery', 'Buscando serviços mDNS...');
    phaseIndex++;
    const results = await discoverServices((msg) => {
      report('service_discovery', msg);
    });
    report('service_discovery', `${results.length} serviços encontrados`);
    return results;
  })();

  // Phase 6: HTTP Inspection — skipped in quick mode
  let httpFindings = quickMode ? [] : await (async () => {
    const httpTargets = portResults
      .filter(pr => HTTP_PORTS.has(pr.port))
      .map(pr => ({ ip: pr.ip, port: pr.port }));
    if (httpTargets.length === 0) return [];

    report('http_inspection', 'Inspecionando serviços HTTP...');
    phaseIndex++;
    const findings = await inspectHttpServices(httpTargets, (msg) => {
      report('http_inspection', msg);
    });
    report('http_inspection', `${findings.length} achados HTTP`);
    return findings;
  })();

  // Phase 7: RTSP Probing — skipped in quick mode
  let rtspFindings = quickMode ? [] : await (async () => {
    const rtspTargets = portResults
      .filter(pr => RTSP_PORTS.has(pr.port))
      .map(pr => ({ ip: pr.ip, port: pr.port }));
    if (rtspTargets.length === 0) return [];

    report('rtsp_probe', 'Verificando serviços RTSP...');
    phaseIndex++;
    const findings = await probeRtsp(rtspTargets, (msg) => {
      report('rtsp_probe', msg);
    });
    report('rtsp_probe', `${findings.filter(f => f.confirmed).length} RTSP confirmados`);
    return findings;
  })();

  // Classification
  report('classification', 'Classificando riscos...');
  const { classifications, counts } = classify(
    ouiResults, portResults, serviceResults, httpFindings, rtspFindings,
  );

  const duration = Math.round((Date.now() - startTime) / 1000);
  report('done', 'Varredura concluída!', `${duration}s`);

  return {
    networkInfo,
    hosts,
    ouiResults,
    portResults,
    serviceResults,
    httpFindings,
    rtspFindings,
    classifications,
    counts,
    duration,
    timestamp: new Date().toISOString(),
    quickMode,
  };
}

function buildEmptyResults(networkInfo: NetworkInfo, quickMode: boolean, startTime: number): ScanResults {
  return {
    networkInfo,
    hosts: [],
    ouiResults: [],
    portResults: [],
    serviceResults: [],
    httpFindings: [],
    rtspFindings: [],
    classifications: [],
    counts: { CRITICAL: 0, HIGH: 0, MODERATE: 0, LOW: 0, INFO: 0 },
    duration: Math.round((Date.now() - startTime) / 1000),
    timestamp: new Date().toISOString(),
    quickMode,
  };
}
