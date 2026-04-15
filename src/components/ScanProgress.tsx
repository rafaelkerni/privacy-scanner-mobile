import React, { useEffect, useRef } from 'react';
import { View, Text, StyleSheet, Animated } from 'react-native';
import { ScanProgress as ScanProgressType, ScanPhase } from '../scanner/types';
import { colors, spacing, fontSize, borderRadius } from '../theme';
import { t, TranslationKey } from '../i18n';

const phaseI18nKeys: Partial<Record<ScanPhase, TranslationKey>> = {
  network_info: 'phase_network_info',
  host_discovery: 'phase_host_discovery',
  oui_analysis: 'phase_oui_analysis',
  port_scan: 'phase_port_scan',
  service_discovery: 'phase_service_discovery',
  http_inspection: 'phase_http_inspection',
  rtsp_probe: 'phase_rtsp_probe',
  classification: 'phase_classification',
  done: 'phase_done',
};

export function ScanProgressView({ progress }: { progress: ScanProgressType }) {
  const pulseAnim = useRef(new Animated.Value(0.3)).current;

  useEffect(() => {
    if (progress.phase === 'done' || progress.phase === 'error') return;
    const animation = Animated.loop(
      Animated.sequence([
        Animated.timing(pulseAnim, { toValue: 1, duration: 800, useNativeDriver: true }),
        Animated.timing(pulseAnim, { toValue: 0.3, duration: 800, useNativeDriver: true }),
      ])
    );
    animation.start();
    return () => animation.stop();
  }, [progress.phase]);

  const progressPct = progress.totalPhases > 0
    ? Math.round((progress.phaseIndex / progress.totalPhases) * 100)
    : 0;

  const phaseKey = phaseI18nKeys[progress.phase];
  const phaseLabel = phaseKey ? t(phaseKey) : progress.message;

  return (
    <View style={styles.container}>
      {/* Radar animation */}
      <View style={styles.radarContainer}>
        <Animated.View style={[styles.radarPulse, { opacity: pulseAnim }]} />
        <View style={styles.radarCenter}>
          <Text style={styles.radarPct}>{progressPct}%</Text>
        </View>
      </View>

      {/* Phase info */}
      <Text style={styles.phaseLabel}>{phaseLabel}</Text>
      {progress.detail ? (
        <Text style={styles.phaseDetail}>{progress.detail}</Text>
      ) : null}
      {progress.message && progress.message !== phaseLabel ? (
        <Text style={styles.phaseMessage}>{progress.message}</Text>
      ) : null}

      {/* Progress bar */}
      <View style={styles.progressBarBg}>
        <View style={[styles.progressBarFill, { width: `${progressPct}%` }]} />
      </View>

      <Text style={styles.phaseCounter}>
        {progress.phaseIndex}/{progress.totalPhases}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    alignItems: 'center',
    paddingVertical: spacing.xl,
  },
  radarContainer: {
    width: 160,
    height: 160,
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: spacing.lg,
  },
  radarPulse: {
    position: 'absolute',
    width: 160,
    height: 160,
    borderRadius: 80,
    borderWidth: 2,
    borderColor: colors.accent,
    backgroundColor: colors.infoBg,
  },
  radarCenter: {
    width: 80,
    height: 80,
    borderRadius: 40,
    backgroundColor: colors.surface,
    borderWidth: 2,
    borderColor: colors.accent,
    justifyContent: 'center',
    alignItems: 'center',
  },
  radarPct: {
    color: colors.accent,
    fontSize: fontSize.xl,
    fontWeight: '700',
    fontFamily: 'monospace',
  },
  phaseLabel: {
    color: colors.textPrimary,
    fontSize: fontSize.lg,
    fontWeight: '600',
    textAlign: 'center',
  },
  phaseDetail: {
    color: colors.textSecondary,
    fontSize: fontSize.sm,
    textAlign: 'center',
    marginTop: spacing.xs,
    fontFamily: 'monospace',
  },
  phaseMessage: {
    color: colors.textMuted,
    fontSize: fontSize.xs,
    textAlign: 'center',
    marginTop: spacing.xs,
  },
  progressBarBg: {
    width: '80%',
    height: 4,
    backgroundColor: colors.border,
    borderRadius: 2,
    marginTop: spacing.lg,
    overflow: 'hidden',
  },
  progressBarFill: {
    height: '100%',
    backgroundColor: colors.accent,
    borderRadius: 2,
  },
  phaseCounter: {
    color: colors.textMuted,
    fontSize: fontSize.xs,
    marginTop: spacing.sm,
    fontFamily: 'monospace',
  },
});
