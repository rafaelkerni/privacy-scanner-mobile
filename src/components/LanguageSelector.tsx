import React from 'react';
import { View, Text, TouchableOpacity, StyleSheet } from 'react-native';
import { Language } from '../i18n';
import { colors, spacing, fontSize, borderRadius } from '../theme';

const LANGS: { code: Language; label: string }[] = [
  { code: 'pt', label: 'PT' },
  { code: 'en', label: 'EN' },
  { code: 'es', label: 'ES' },
];

interface Props {
  current: Language;
  onChange: (lang: Language) => void;
}

export function LanguageSelector({ current, onChange }: Props) {
  return (
    <View style={styles.container}>
      {LANGS.map(({ code, label }) => (
        <TouchableOpacity
          key={code}
          onPress={() => onChange(code)}
          style={[
            styles.button,
            current === code && styles.buttonActive,
          ]}
        >
          <Text style={[
            styles.label,
            current === code && styles.labelActive,
          ]}>
            {label}
          </Text>
        </TouchableOpacity>
      ))}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flexDirection: 'row',
    backgroundColor: colors.surface,
    borderRadius: borderRadius.full,
    borderWidth: 1,
    borderColor: colors.border,
    padding: 2,
  },
  button: {
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.xs,
    borderRadius: borderRadius.full,
  },
  buttonActive: {
    backgroundColor: colors.accent,
  },
  label: {
    color: colors.textSecondary,
    fontSize: fontSize.xs,
    fontWeight: '600',
  },
  labelActive: {
    color: colors.white,
  },
});
