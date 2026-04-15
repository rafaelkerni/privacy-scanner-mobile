export const CAMERA_PORTS = [
  554, 8554,           // RTSP
  80, 443, 8080, 8443, // HTTP/HTTPS
  8000, 8200,          // Hikvision
  37777,               // Dahua
  34567, 34599,        // XMEye/Chinese NVR
  9000,                // Reolink
  3702,                // ONVIF WS-Discovery
  1935,                // RTMP
  5000,                // Synology/QNAP Surveillance
  6667,                // Alt RTSP
  8899,                // Alt HTTP camera
  49152,               // UPnP control
  7070,                // Alt streaming
  9527,                // Chinese camera debug
] as const;

export const RTSP_PORTS = new Set([554, 8554]);
export const HTTP_PORTS = new Set([80, 443, 8080, 8443, 8899]);
export const VENDOR_PORTS = new Set([8000, 8200, 37777, 34567, 34599, 9000]);

export const VENDOR_PORT_NAMES: Record<number, string> = {
  8000: 'Hikvision SDK',
  8200: 'Hikvision Web Alt',
  37777: 'Dahua Protocol',
  34567: 'XMEye/Chinese NVR',
  34599: 'XMEye Alt',
  9000: 'Reolink',
};
