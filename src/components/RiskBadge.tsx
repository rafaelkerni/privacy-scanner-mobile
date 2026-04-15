import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { RiskLevel } from '../scanner/types';
import { riskColors, borderRadius, fontSize, spacing } from '../theme';
import { t } from '../i18n';

const riskLabels: Record<RiskLevel, () => string> = {
  CRITICAL: () => t('critical'),
  HIGH: () => t('high'),
  MODERATE: () => t('moderate'),
  LOW: () => t('low'),
  INFO: () => t('info'),
};

export function RiskBadge({ level, size = 'md' }: { level: RiskLevel; size?: 'sm' | 'md' }) {
  const colors = riskColors[level];
  const isSmall = size === 'sm';

  return (
    <View style={[
      styles.badge,
      { backgroundColor: colors.bg, borderColor: colors.border },
      isSmall && styles.badgeSmall,
    ]}>
      <Text style={[
        styles.text,
        { color: colors.text },
        isSmall && styles.textSmall,
      ]}>
        {riskLabels[level]()}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  badge: {
    paddingHorizontal: spacing.sm,
    paddingVertical: spacing.xs,
    borderRadius: borderRadius.sm,
    borderWidth: 1,
    alignSelf: 'flex-start',
  },
  badgeSmall: {
    paddingHorizontal: 6,
    paddingVertical: 2,
  },
  text: {
    fontSize: fontSize.sm,
    fontWeight: '700',
    textTransform: 'uppercase',
    letterSpacing: 0.5,
  },
  textSmall: {
    fontSize: fontSize.xs,
  },
});
