export const CAMERA_KEYWORDS_HIGH = [
  'camera', 'webcam', 'ipcam', 'DVR', 'NVR', 'surveillance', 'CCTV',
  'hikvision', 'dahua', 'amcrest', 'reolink', 'foscam', 'wyze',
  'ONVIF', 'rtsp://', 'liveview', 'live view', 'snapshot',
  'motion detect', 'PTZ', 'night vision',
  'DNVRS-Webs', 'App-webs', 'XMEye', 'NETSurveillance',
  'IPCamera', 'webcamXP', 'Yawcam', 'Blue Iris', 'ZoneMinder',
  'Shinobi', 'MotionEye', 'Frigate', 'ISAPI',
  'Streaming/Channels', 'cam/realmonitor',
] as const;

export const CAMERA_KEYWORDS_MEDIUM = [
  'stream', 'video', 'media server', 'MJPEG', 'H.264', 'H.265',
  'codec', 'bitrate', 'firmware', 'device info',
] as const;

export const CAMERA_HEADERS = [
  'DNVRS-Webs', 'App-webs', 'Hikvision', 'Dahua', 'DH-IPC',
  'uc-httpd', 'GoAhead-Webs', 'JAWS/', 'Boa/',
] as const;

export const CAMERA_TITLES = [
  'NETSurveillance', 'DVR', 'NVR', 'IPCamera', 'IP Camera',
  'Network Camera', 'iVMS', 'SADP', 'webcamXP', 'Yawcam',
  'Blue Iris', 'ZoneMinder', 'Shinobi', 'MotionEye', 'Frigate',
] as const;

export const SAFE_MANUFACTURERS = [
  'apple', 'samsung electronics', 'intel', 'dell', 'hewlett', 'lenovo',
  'huawei device', 'xiaomi comm', 'google', 'amazon', 'sonos', 'roku',
  'brother', 'canon', 'philips', 'ecobee', 'honeywell', 'microsoft',
] as const;

export const IOT_CHIPSETS = ['espressif', 'tuya', 'smartlife', 'beken'] as const;

export const GENERIC_CHIPSETS = [
  'realtek', 'mediatek', 'qualcomm', 'broadcom', 'marvell', 'ralink',
] as const;

export const CAMERA_MFR_KEYWORDS = [
  'camera', 'surveillance', 'security', 'cctv', 'dvr', 'nvr', 'vision',
] as const;

export const MDNS_CAMERA_SERVICES = [
  '_rtsp._tcp.',
  '_camera._tcp.',
  '_nvr._tcp.',
  '_onvif._tcp.',
] as const;

export const MDNS_ALL_SERVICES = [
  ...MDNS_CAMERA_SERVICES,
  '_http._tcp.',
] as const;
