import { RiskLevel } from '../scanner/types';

export const colors = {
  background: '#0D1117',
  surface: '#161B22',
  card: '#1C2128',
  cardBorder: '#30363D',
  border: '#21262D',

  textPrimary: '#E6EDF3',
  textSecondary: '#8B949E',
  textMuted: '#484F58',

  accent: '#58A6FF',
  accentDim: '#1F6FEB',

  critical: '#F85149',
  criticalBg: '#3D1114',
  high: '#D29922',
  highBg: '#3D2E00',
  moderate: '#E3B341',
  moderateBg: '#3D3000',
  low: '#3FB950',
  lowBg: '#0D3117',
  info: '#58A6FF',
  infoBg: '#0D2240',

  white: '#FFFFFF',
  black: '#010409',
  transparent: 'transparent',
} as const;

export const riskColors: Record<RiskLevel, { text: string; bg: string; border: string }> = {
  CRITICAL: { text: colors.critical, bg: colors.criticalBg, border: colors.critical },
  HIGH: { text: colors.high, bg: colors.highBg, border: colors.high },
  MODERATE: { text: colors.moderate, bg: colors.moderateBg, border: colors.moderate },
  LOW: { text: colors.low, bg: colors.lowBg, border: colors.low },
  INFO: { text: colors.info, bg: colors.infoBg, border: colors.info },
};

export const spacing = {
  xs: 4,
  sm: 8,
  md: 16,
  lg: 24,
  xl: 32,
  xxl: 48,
} as const;

export const fontSize = {
  xs: 11,
  sm: 13,
  md: 15,
  lg: 18,
  xl: 22,
  xxl: 28,
  hero: 36,
} as const;

export const borderRadius = {
  sm: 6,
  md: 10,
  lg: 16,
  full: 999,
} as const;
