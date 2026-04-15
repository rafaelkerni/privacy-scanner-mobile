import React, { useState } from 'react';
import { View, Text, StyleSheet, TouchableOpacity } from 'react-native';
import { DeviceClassification } from '../scanner/types';
import { RiskBadge } from './RiskBadge';
import { colors, riskColors, spacing, fontSize, borderRadius } from '../theme';
import { t } from '../i18n';

export function DeviceCard({ device }: { device: DeviceClassification }) {
  const [expanded, setExpanded] = useState(device.risk === 'CRITICAL' || device.risk === 'HIGH');
  const rc = riskColors[device.risk];

  return (
    <TouchableOpacity
      activeOpacity={0.7}
      onPress={() => setExpanded(!expanded)}
      style={[styles.card, { borderLeftColor: rc.border }]}
    >
      <View style={styles.header}>
        <View style={styles.headerLeft}>
          <Text style={styles.ip}>{device.ip}</Text>
          <Text style={styles.deviceType}>{device.deviceType}</Text>
        </View>
        <RiskBadge level={device.risk} />
      </View>

      {expanded && (
        <View style={styles.details}>
          <DetailRow label={t('manufacturer')} value={device.manufacturer || 'Unknown'} />
          <DetailRow label="MAC" value={device.mac} />
          {device.openPorts ? (
            <DetailRow label={t('openPorts')} value={device.openPorts} highlight />
          ) : null}
          <DetailRow label={t('evidence')} value={device.evidence} />
          <View style={styles.recommendationBox}>
            <Text style={[styles.recommendationText, { color: rc.text }]}>
              {device.recommendation}
            </Text>
          </View>
        </View>
      )}

      <Text style={styles.expandHint}>
        {expanded ? '▲' : '▼'}
      </Text>
    </TouchableOpacity>
  );
}

function DetailRow({ label, value, highlight }: { label: string; value: string; highlight?: boolean }) {
  return (
    <View style={styles.detailRow}>
      <Text style={styles.detailLabel}>{label}</Text>
      <Text style={[styles.detailValue, highlight && styles.detailHighlight]}>
        {value}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    backgroundColor: colors.card,
    borderRadius: borderRadius.md,
    borderWidth: 1,
    borderColor: colors.cardBorder,
    borderLeftWidth: 4,
    marginBottom: spacing.sm,
    padding: spacing.md,
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
  },
  headerLeft: {
    flex: 1,
    marginRight: spacing.sm,
  },
  ip: {
    color: colors.textPrimary,
    fontSize: fontSize.lg,
    fontWeight: '600',
    fontFamily: 'monospace',
  },
  deviceType: {
    color: colors.textSecondary,
    fontSize: fontSize.sm,
    marginTop: 2,
  },
  details: {
    marginTop: spacing.md,
    borderTopWidth: 1,
    borderTopColor: colors.border,
    paddingTop: spacing.md,
  },
  detailRow: {
    marginBottom: spacing.sm,
  },
  detailLabel: {
    color: colors.textMuted,
    fontSize: fontSize.xs,
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    marginBottom: 2,
  },
  detailValue: {
    color: colors.textPrimary,
    fontSize: fontSize.sm,
    fontFamily: 'monospace',
  },
  detailHighlight: {
    color: colors.high,
  },
  recommendationBox: {
    backgroundColor: colors.surface,
    borderRadius: borderRadius.sm,
    padding: spacing.sm,
    marginTop: spacing.xs,
  },
  recommendationText: {
    fontSize: fontSize.sm,
    fontWeight: '500',
    lineHeight: 20,
  },
  expandHint: {
    color: colors.textMuted,
    fontSize: fontSize.xs,
    textAlign: 'center',
    marginTop: spacing.xs,
  },
});
