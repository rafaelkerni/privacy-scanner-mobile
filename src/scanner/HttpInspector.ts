import { HttpFinding } from './types';
import {
  CAMERA_KEYWORDS_HIGH,
  CAMERA_KEYWORDS_MEDIUM,
  CAMERA_HEADERS,
  CAMERA_TITLES,
} from '../data/keywords';

const HTTP_TIMEOUT = 5000;

function matchesKeywords(text: string, keywords: readonly string[]): string[] {
  const lower = text.toLowerCase();
  return keywords.filter(k => lower.includes(k.toLowerCase()));
}

async function inspectEndpoint(ip: string, port: number): Promise<HttpFinding[]> {
  const findings: HttpFinding[] = [];
  const proto = port === 443 || port === 8443 ? 'https' : 'http';
  const url = `${proto}://${ip}:${port}/`;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), HTTP_TIMEOUT);

    const response = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
      // @ts-ignore — React Native supports these options
      headers: { 'User-Agent': 'Mozilla/5.0' },
    });

    clearTimeout(timeoutId);

    // Check server header
    const serverHeader = response.headers.get('server') ?? '';
    const headerMatches = matchesKeywords(serverHeader, CAMERA_HEADERS);
    if (headerMatches.length > 0) {
      findings.push({
        ip, port,
        type: 'CAMERA_HEADER',
        detail: serverHeader,
      });
    }

    // Read body (limited to ~50KB)
    let body = '';
    try {
      body = await response.text();
      if (body.length > 51200) body = body.substring(0, 51200);
    } catch {}

    // Check body for high-confidence keywords
    const highMatches = matchesKeywords(body, CAMERA_KEYWORDS_HIGH);
    if (highMatches.length > 0) {
      findings.push({
        ip, port,
        type: 'CAMERA_WEBUI',
        detail: highMatches.slice(0, 5).join(', '),
      });
    } else {
      // Check medium-confidence keywords
      const medMatches = matchesKeywords(body, CAMERA_KEYWORDS_MEDIUM);
      if (medMatches.length > 0) {
        findings.push({
          ip, port,
          type: 'POSSIBLE_CAMERA',
          detail: medMatches.slice(0, 5).join(', '),
        });
      }
    }

    // Check HTML title
    const titleMatch = body.match(/<title>([^<]+)<\/title>/i);
    if (titleMatch) {
      const title = titleMatch[1];
      const titleMatches = matchesKeywords(title, CAMERA_TITLES);
      if (titleMatches.length > 0) {
        findings.push({
          ip, port,
          type: 'CAMERA_TITLE',
          detail: title,
        });
      }
    }
  } catch {
    // Connection failed or timed out — not an HTTP service
  }

  return findings;
}

export async function inspectHttpServices(
  targets: Array<{ ip: string; port: number }>,
  onProgress?: (msg: string) => void,
): Promise<HttpFinding[]> {
  const allFindings: HttpFinding[] = [];

  for (let i = 0; i < targets.length; i++) {
    const { ip, port } = targets[i];
    onProgress?.(`HTTP ${ip}:${port} (${i + 1}/${targets.length})`);

    const findings = await inspectEndpoint(ip, port);
    allFindings.push(...findings);
  }

  return allFindings;
}
