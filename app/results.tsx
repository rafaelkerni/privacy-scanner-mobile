import React, { useState } from 'react';
import { View, Text, StyleSheet, ScrollView, TouchableOpacity, Share } from 'react-native';
import { useRouter } from 'expo-router';
import { useScan } from '../src/context/ScanContext';
import { DeviceCard } from '../src/components/DeviceCard';
import { RiskSummary } from '../src/components/RiskSummary';
import { ActionGuide } from '../src/components/ActionGuide';
import { LanguageSelector } from '../src/components/LanguageSelector';
import { colors, spacing, fontSize, borderRadius } from '../src/theme';
import { t } from '../src/i18n';

export default function ResultsScreen() {
  const router = useRouter();
  const { results, clearResults, language, changeLanguage } = useScan();
  const [, forceUpdate] = useState(0);

  if (!results) {
    router.replace('/');
    return null;
  }

  const { classifications, counts, networkInfo, duration, quickMode } = results;
  const hasThreat = counts.CRITICAL > 0;
  const hasSuspicious = counts.HIGH > 0;

  const handleChangeLanguage = (lang: typeof language) => {
    changeLanguage(lang);
    forceUpdate(n => n + 1);
  };

  const handleShare = async () => {
    const lines = [
      `PRIVACY SCANNER - ${t('results')}`,
      `${new Date().toLocaleString()}`,
      ``,
      `${t('network')}: ${networkInfo.ssid} (${networkInfo.subnet})`,
      `${t('duration')}: ${duration}s | ${t('mode')}: ${quickMode ? t('quick') : t('full')}`,
      ``,
      `--- ${t('riskSummary')} ---`,
      `${t('critical')}: ${counts.CRITICAL}`,
      `${t('high')}: ${counts.HIGH}`,
      `${t('moderate')}: ${counts.MODERATE}`,
      `${t('low')}: ${counts.LOW}`,
      `${t('info')}: ${counts.INFO}`,
      ``,
      `--- ${t('deviceDetails')} ---`,
    ];

    for (const d of classifications) {
      lines.push(`[${d.risk}] ${d.ip} - ${d.deviceType}`);
      lines.push(`  MAC: ${d.mac} | ${d.manufacturer}`);
      if (d.openPorts) lines.push(`  Ports: ${d.openPorts}`);
      lines.push(`  ${d.evidence}`);
      lines.push(``);
    }

    try {
      await Share.share({ message: lines.join('\n'), title: 'Privacy Scanner Report' });
    } catch {}
  };

  const handleScanAgain = () => {
    clearResults();
    router.replace('/');
  };

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
    >
      {/* Header */}
      <View style={styles.header}>
        <View style={styles.headerTop}>
          <Text style={styles.title}>{t('scanComplete')}</Text>
          <LanguageSelector current={language} onChange={handleChangeLanguage} />
        </View>

        {/* Network info */}
        <View style={styles.networkInfo}>
          <InfoPill label={t('network')} value={networkInfo.ssid || networkInfo.subnet} />
          <InfoPill label={t('gateway')} value={networkInfo.gateway} />
          <InfoPill label={t('duration')} value={`${duration}s`} />
          <InfoPill label={t('mode')} value={quickMode ? t('quick') : t('full')} />
        </View>
      </View>

      {/* Threat banner */}
      {hasThreat && (
        <View style={styles.threatBanner}>
          <Text style={styles.threatIcon}>⚠</Text>
          <Text style={styles.threatText}>{t('threatDetected')}</Text>
        </View>
      )}
      {!hasThreat && hasSuspicious && (
        <View style={styles.suspiciousBanner}>
          <Text style={styles.suspiciousIcon}>⚡</Text>
          <Text style={styles.suspiciousText}>{t('suspiciousDetected')}</Text>
        </View>
      )}
      {!hasThreat && !hasSuspicious && (
        <View style={styles.clearBanner}>
          <Text style={styles.clearIcon}>✓</Text>
          <Text style={styles.clearText}>{t('allClear')}</Text>
        </View>
      )}

      {/* Risk summary */}
      <RiskSummary counts={counts} />

      {/* Action guide if threats */}
      {(hasThreat || hasSuspicious) && <ActionGuide />}

      {/* Device list */}
      <Text style={styles.sectionTitle}>
        {t('deviceDetails')} ({classifications.length} {t('devicesFound')})
      </Text>

      {classifications.length === 0 ? (
        <View style={styles.emptyBox}>
          <Text style={styles.emptyText}>{t('noDevices')}</Text>
        </View>
      ) : (
        classifications.map((device, i) => (
          <DeviceCard key={`${device.ip}-${i}`} device={device} />
        ))
      )}

      {/* Action buttons */}
      <View style={styles.actions}>
        <TouchableOpacity
          style={styles.shareButton}
          onPress={handleShare}
          activeOpacity={0.8}
        >
          <Text style={styles.shareButtonText}>{t('shareReport')}</Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.scanAgainButton}
          onPress={handleScanAgain}
          activeOpacity={0.8}
        >
          <Text style={styles.scanAgainText}>{t('scanAgain')}</Text>
        </TouchableOpacity>
      </View>
    </ScrollView>
  );
}

function InfoPill({ label, value }: { label: string; value: string }) {
  return (
    <View style={styles.pill}>
      <Text style={styles.pillLabel}>{label}</Text>
      <Text style={styles.pillValue}>{value}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.background,
  },
  content: {
    padding: spacing.lg,
    paddingTop: spacing.xxl,
    paddingBottom: spacing.xxl,
  },
  header: {
    marginBottom: spacing.md,
  },
  headerTop: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: spacing.md,
  },
  title: {
    color: colors.textPrimary,
    fontSize: fontSize.xl,
    fontWeight: '700',
  },
  networkInfo: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: spacing.xs,
  },
  pill: {
    backgroundColor: colors.surface,
    borderRadius: borderRadius.sm,
    paddingHorizontal: spacing.sm,
    paddingVertical: spacing.xs,
    borderWidth: 1,
    borderColor: colors.border,
  },
  pillLabel: {
    color: colors.textMuted,
    fontSize: 9,
    textTransform: 'uppercase',
    letterSpacing: 0.5,
  },
  pillValue: {
    color: colors.textPrimary,
    fontSize: fontSize.xs,
    fontFamily: 'monospace',
  },
  threatBanner: {
    backgroundColor: colors.criticalBg,
    borderRadius: borderRadius.md,
    borderWidth: 1,
    borderColor: colors.critical,
    padding: spacing.md,
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: spacing.md,
  },
  threatIcon: {
    fontSize: 24,
    marginRight: spacing.sm,
  },
  threatText: {
    color: colors.critical,
    fontSize: fontSize.sm,
    fontWeight: '700',
    flex: 1,
    textTransform: 'uppercase',
  },
  suspiciousBanner: {
    backgroundColor: colors.highBg,
    borderRadius: borderRadius.md,
    borderWidth: 1,
    borderColor: colors.high,
    padding: spacing.md,
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: spacing.md,
  },
  suspiciousIcon: {
    fontSize: 24,
    marginRight: spacing.sm,
  },
  suspiciousText: {
    color: colors.high,
    fontSize: fontSize.sm,
    fontWeight: '700',
    flex: 1,
  },
  clearBanner: {
    backgroundColor: colors.lowBg,
    borderRadius: borderRadius.md,
    borderWidth: 1,
    borderColor: colors.low,
    padding: spacing.md,
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: spacing.md,
  },
  clearIcon: {
    fontSize: 24,
    color: colors.low,
    marginRight: spacing.sm,
  },
  clearText: {
    color: colors.low,
    fontSize: fontSize.sm,
    fontWeight: '700',
    flex: 1,
  },
  sectionTitle: {
    color: colors.textPrimary,
    fontSize: fontSize.md,
    fontWeight: '600',
    marginBottom: spacing.md,
    marginTop: spacing.sm,
  },
  emptyBox: {
    backgroundColor: colors.surface,
    borderRadius: borderRadius.md,
    padding: spacing.xl,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: colors.border,
  },
  emptyText: {
    color: colors.textMuted,
    fontSize: fontSize.md,
  },
  actions: {
    marginTop: spacing.lg,
    gap: spacing.sm,
  },
  shareButton: {
    backgroundColor: colors.accent,
    borderRadius: borderRadius.md,
    paddingVertical: spacing.md,
    alignItems: 'center',
  },
  shareButtonText: {
    color: colors.white,
    fontSize: fontSize.md,
    fontWeight: '700',
  },
  scanAgainButton: {
    backgroundColor: colors.surface,
    borderRadius: borderRadius.md,
    borderWidth: 1,
    borderColor: colors.border,
    paddingVertical: spacing.md,
    alignItems: 'center',
  },
  scanAgainText: {
    color: colors.textPrimary,
    fontSize: fontSize.md,
    fontWeight: '600',
  },
});
