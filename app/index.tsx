import React, { useState } from 'react';
import {
  View, Text, StyleSheet, TouchableOpacity, ScrollView, Platform,
  PermissionsAndroid,
} from 'react-native';
import { useRouter } from 'expo-router';
import { useScan } from '../src/context/ScanContext';
import { LanguageSelector } from '../src/components/LanguageSelector';
import { colors, spacing, fontSize, borderRadius } from '../src/theme';
import { t } from '../src/i18n';

async function requestPermissions(): Promise<boolean> {
  if (Platform.OS !== 'android') return true;
  try {
    const granted = await PermissionsAndroid.request(
      PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION,
      {
        title: t('permissionTitle'),
        message: t('permissionMsg'),
        buttonPositive: t('grant'),
      },
    );
    return granted === PermissionsAndroid.RESULTS.GRANTED;
  } catch {
    return false;
  }
}

export default function HomeScreen() {
  const router = useRouter();
  const { startScan, language, changeLanguage } = useScan();
  const [, forceUpdate] = useState(0);

  const handleChangeLanguage = (lang: typeof language) => {
    changeLanguage(lang);
    forceUpdate(n => n + 1); // Force re-render for i18n
  };

  const handleScan = async (quickMode: boolean) => {
    const hasPermission = await requestPermissions();
    if (!hasPermission) return;

    startScan(quickMode);
    router.push('/scan');
  };

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
    >
      {/* Header */}
      <View style={styles.header}>
        <View style={styles.langRow}>
          <LanguageSelector current={language} onChange={handleChangeLanguage} />
        </View>

        <View style={styles.logoContainer}>
          <View style={styles.logoCircle}>
            <Text style={styles.logoIcon}>◎</Text>
          </View>
        </View>

        <Text style={styles.title}>{t('appName')}</Text>
        <Text style={styles.subtitle}>{t('appSubtitle')}</Text>
      </View>

      {/* Scan buttons */}
      <View style={styles.buttonSection}>
        <TouchableOpacity
          style={styles.primaryButton}
          onPress={() => handleScan(false)}
          activeOpacity={0.8}
        >
          <Text style={styles.primaryButtonIcon}>⬡</Text>
          <View>
            <Text style={styles.primaryButtonText}>{t('fullScan')}</Text>
            <Text style={styles.buttonSubtext}>7 fases • ~3-5 min</Text>
          </View>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.secondaryButton}
          onPress={() => handleScan(true)}
          activeOpacity={0.8}
        >
          <Text style={styles.secondaryButtonIcon}>◇</Text>
          <View>
            <Text style={styles.secondaryButtonText}>{t('quickScan')}</Text>
            <Text style={styles.buttonSubtext}>5 fases • ~1-2 min</Text>
          </View>
        </TouchableOpacity>
      </View>

      {/* Info section */}
      <View style={styles.infoSection}>
        <Text style={styles.infoTitle}>Como funciona</Text>
        <InfoItem number="1" text="Descobre todos os dispositivos na rede WiFi" />
        <InfoItem number="2" text="Identifica fabricantes por endereço MAC (OUI)" />
        <InfoItem number="3" text="Escaneia portas específicas de câmeras" />
        <InfoItem number="4" text="Busca serviços mDNS de câmeras" />
        <InfoItem number="5" text="Inspeciona interfaces web e RTSP" />
        <InfoItem number="6" text="Classifica risco de cada dispositivo" />
      </View>

      {/* Disclaimer */}
      <View style={styles.disclaimer}>
        <Text style={styles.disclaimerText}>{t('disclaimer')}</Text>
      </View>
    </ScrollView>
  );
}

function InfoItem({ number, text }: { number: string; text: string }) {
  return (
    <View style={styles.infoItem}>
      <View style={styles.infoNumber}>
        <Text style={styles.infoNumberText}>{number}</Text>
      </View>
      <Text style={styles.infoText}>{text}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.background,
  },
  content: {
    paddingHorizontal: spacing.lg,
    paddingTop: spacing.xxl,
    paddingBottom: spacing.xxl,
  },
  header: {
    alignItems: 'center',
    marginBottom: spacing.xl,
  },
  langRow: {
    alignSelf: 'flex-end',
    marginBottom: spacing.lg,
  },
  logoContainer: {
    marginBottom: spacing.md,
  },
  logoCircle: {
    width: 80,
    height: 80,
    borderRadius: 40,
    backgroundColor: colors.infoBg,
    borderWidth: 2,
    borderColor: colors.accent,
    justifyContent: 'center',
    alignItems: 'center',
  },
  logoIcon: {
    fontSize: 36,
    color: colors.accent,
  },
  title: {
    color: colors.textPrimary,
    fontSize: fontSize.hero,
    fontWeight: '700',
    letterSpacing: -1,
  },
  subtitle: {
    color: colors.textSecondary,
    fontSize: fontSize.md,
    marginTop: spacing.xs,
  },
  buttonSection: {
    gap: spacing.md,
    marginBottom: spacing.xl,
  },
  primaryButton: {
    backgroundColor: colors.accent,
    borderRadius: borderRadius.lg,
    paddingVertical: spacing.lg,
    paddingHorizontal: spacing.lg,
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.md,
  },
  primaryButtonIcon: {
    fontSize: 28,
    color: colors.white,
  },
  primaryButtonText: {
    color: colors.white,
    fontSize: fontSize.lg,
    fontWeight: '700',
  },
  secondaryButton: {
    backgroundColor: colors.surface,
    borderRadius: borderRadius.lg,
    borderWidth: 1,
    borderColor: colors.border,
    paddingVertical: spacing.lg,
    paddingHorizontal: spacing.lg,
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.md,
  },
  secondaryButtonIcon: {
    fontSize: 28,
    color: colors.accent,
  },
  secondaryButtonText: {
    color: colors.textPrimary,
    fontSize: fontSize.lg,
    fontWeight: '600',
  },
  buttonSubtext: {
    color: colors.textMuted,
    fontSize: fontSize.xs,
    marginTop: 2,
  },
  infoSection: {
    backgroundColor: colors.surface,
    borderRadius: borderRadius.md,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.md,
    marginBottom: spacing.md,
  },
  infoTitle: {
    color: colors.textPrimary,
    fontSize: fontSize.md,
    fontWeight: '600',
    marginBottom: spacing.md,
  },
  infoItem: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: spacing.sm,
  },
  infoNumber: {
    width: 22,
    height: 22,
    borderRadius: 11,
    backgroundColor: colors.border,
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: spacing.sm,
  },
  infoNumberText: {
    color: colors.textSecondary,
    fontSize: fontSize.xs,
    fontWeight: '700',
  },
  infoText: {
    color: colors.textSecondary,
    fontSize: fontSize.sm,
    flex: 1,
  },
  disclaimer: {
    backgroundColor: colors.card,
    borderRadius: borderRadius.sm,
    padding: spacing.md,
    borderWidth: 1,
    borderColor: colors.border,
  },
  disclaimerText: {
    color: colors.textMuted,
    fontSize: fontSize.xs,
    lineHeight: 18,
    textAlign: 'center',
  },
});
