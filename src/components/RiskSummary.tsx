import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { RiskCounts, RiskLevel } from '../scanner/types';
import { colors, riskColors, spacing, fontSize, borderRadius } from '../theme';
import { t } from '../i18n';

const levels: RiskLevel[] = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'INFO'];

export function RiskSummary({ counts }: { counts: RiskCounts }) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (total === 0) return null;

  return (
    <View style={styles.container}>
      <Text style={styles.title}>{t('riskSummary')}</Text>

      {/* Distribution bar */}
      <View style={styles.bar}>
        {levels.map(level => {
          const count = counts[level];
          if (count === 0) return null;
          const pct = (count / total) * 100;
          return (
            <View
              key={level}
              style={[styles.barSegment, {
                width: `${pct}%`,
                backgroundColor: riskColors[level].text,
              }]}
            />
          );
        })}
      </View>

      {/* Counts grid */}
      <View style={styles.grid}>
        {levels.map(level => (
          <View key={level} style={styles.countItem}>
            <View style={[styles.dot, { backgroundColor: riskColors[level].text }]} />
            <Text style={styles.countValue}>{counts[level]}</Text>
            <Text style={styles.countLabel}>
              {t(level.toLowerCase() as any)}
            </Text>
          </View>
        ))}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    backgroundColor: colors.card,
    borderRadius: borderRadius.md,
    borderWidth: 1,
    borderColor: colors.cardBorder,
    padding: spacing.md,
    marginBottom: spacing.md,
  },
  title: {
    color: colors.textPrimary,
    fontSize: fontSize.md,
    fontWeight: '600',
    marginBottom: spacing.md,
  },
  bar: {
    flexDirection: 'row',
    height: 8,
    borderRadius: 4,
    overflow: 'hidden',
    backgroundColor: colors.border,
    marginBottom: spacing.md,
  },
  barSegment: {
    height: '100%',
  },
  grid: {
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  countItem: {
    alignItems: 'center',
    flex: 1,
  },
  dot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    marginBottom: 4,
  },
  countValue: {
    color: colors.textPrimary,
    fontSize: fontSize.lg,
    fontWeight: '700',
    fontFamily: 'monospace',
  },
  countLabel: {
    color: colors.textMuted,
    fontSize: fontSize.xs,
    textTransform: 'uppercase',
  },
});
