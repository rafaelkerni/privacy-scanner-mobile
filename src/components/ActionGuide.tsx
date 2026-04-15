import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { colors, spacing, fontSize, borderRadius } from '../theme';
import { t } from '../i18n';

export function ActionGuide() {
  const actions = [
    t('action1'),
    t('action2'),
    t('action3'),
    t('action4'),
    t('action5'),
  ];

  return (
    <View style={styles.container}>
      <Text style={styles.title}>{t('actionGuideTitle')}</Text>

      {actions.map((action, i) => (
        <View key={i} style={styles.actionRow}>
          <View style={styles.numberCircle}>
            <Text style={styles.number}>{i + 1}</Text>
          </View>
          <Text style={styles.actionText}>{action}</Text>
        </View>
      ))}

      <View style={styles.policiesSection}>
        <Text style={styles.policyText}>{t('airbnbPolicy')}</Text>
        <Text style={styles.policyText}>{t('bookingPolicy')}</Text>
        <Text style={styles.policyText}>{t('vrboPolicy')}</Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    backgroundColor: colors.criticalBg,
    borderRadius: borderRadius.md,
    borderWidth: 1,
    borderColor: colors.critical,
    padding: spacing.md,
    marginBottom: spacing.md,
  },
  title: {
    color: colors.critical,
    fontSize: fontSize.lg,
    fontWeight: '700',
    marginBottom: spacing.md,
    textTransform: 'uppercase',
  },
  actionRow: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    marginBottom: spacing.sm,
  },
  numberCircle: {
    width: 24,
    height: 24,
    borderRadius: 12,
    backgroundColor: colors.critical,
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: spacing.sm,
    marginTop: 2,
  },
  number: {
    color: colors.white,
    fontSize: fontSize.xs,
    fontWeight: '700',
  },
  actionText: {
    color: colors.textPrimary,
    fontSize: fontSize.sm,
    flex: 1,
    lineHeight: 22,
  },
  policiesSection: {
    marginTop: spacing.md,
    paddingTop: spacing.md,
    borderTopWidth: 1,
    borderTopColor: colors.critical + '33',
  },
  policyText: {
    color: colors.textSecondary,
    fontSize: fontSize.xs,
    marginBottom: spacing.xs,
    lineHeight: 18,
  },
});
