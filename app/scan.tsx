import React, { useEffect } from 'react';
import { View, Text, StyleSheet, TouchableOpacity } from 'react-native';
import { useRouter } from 'expo-router';
import { useScan } from '../src/context/ScanContext';
import { ScanProgressView } from '../src/components/ScanProgress';
import { colors, spacing, fontSize, borderRadius } from '../src/theme';

export default function ScanScreen() {
  const router = useRouter();
  const { progress, isScanning, results, error } = useScan();

  // Navigate to results when scan completes
  useEffect(() => {
    if (!isScanning && results) {
      router.replace('/results');
    }
  }, [isScanning, results]);

  return (
    <View style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.title}>Privacy Scanner</Text>
        <Text style={styles.subtitle}>
          {isScanning ? 'Varredura em andamento...' : 'Concluído'}
        </Text>
      </View>

      {/* Progress */}
      {progress && <ScanProgressView progress={progress} />}

      {/* Error */}
      {error && (
        <View style={styles.errorBox}>
          <Text style={styles.errorTitle}>Erro</Text>
          <Text style={styles.errorText}>{error}</Text>
          <TouchableOpacity
            style={styles.errorButton}
            onPress={() => router.back()}
          >
            <Text style={styles.errorButtonText}>Voltar</Text>
          </TouchableOpacity>
        </View>
      )}

      {/* Scan tips */}
      {isScanning && (
        <View style={styles.tipsBox}>
          <Text style={styles.tipsTitle}>Dicas durante a varredura</Text>
          <Text style={styles.tipText}>• Mantenha-se conectado à rede WiFi</Text>
          <Text style={styles.tipText}>• O scan pode levar alguns minutos</Text>
          <Text style={styles.tipText}>• Não feche o aplicativo</Text>
        </View>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.background,
    paddingHorizontal: spacing.lg,
    paddingTop: spacing.xxl,
  },
  header: {
    alignItems: 'center',
    marginBottom: spacing.lg,
  },
  title: {
    color: colors.textPrimary,
    fontSize: fontSize.xl,
    fontWeight: '700',
  },
  subtitle: {
    color: colors.textSecondary,
    fontSize: fontSize.sm,
    marginTop: spacing.xs,
  },
  errorBox: {
    backgroundColor: colors.criticalBg,
    borderRadius: borderRadius.md,
    borderWidth: 1,
    borderColor: colors.critical,
    padding: spacing.lg,
    alignItems: 'center',
  },
  errorTitle: {
    color: colors.critical,
    fontSize: fontSize.lg,
    fontWeight: '700',
    marginBottom: spacing.sm,
  },
  errorText: {
    color: colors.textPrimary,
    fontSize: fontSize.sm,
    textAlign: 'center',
    marginBottom: spacing.md,
    lineHeight: 22,
  },
  errorButton: {
    backgroundColor: colors.critical,
    paddingHorizontal: spacing.lg,
    paddingVertical: spacing.sm,
    borderRadius: borderRadius.sm,
  },
  errorButtonText: {
    color: colors.white,
    fontSize: fontSize.md,
    fontWeight: '600',
  },
  tipsBox: {
    backgroundColor: colors.surface,
    borderRadius: borderRadius.md,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.md,
    marginTop: spacing.lg,
  },
  tipsTitle: {
    color: colors.textSecondary,
    fontSize: fontSize.sm,
    fontWeight: '600',
    marginBottom: spacing.sm,
  },
  tipText: {
    color: colors.textMuted,
    fontSize: fontSize.xs,
    lineHeight: 20,
  },
});
