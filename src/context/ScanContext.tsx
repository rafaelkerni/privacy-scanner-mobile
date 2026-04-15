import React, { createContext, useContext, useState, useCallback, ReactNode } from 'react';
import { ScanResults, ScanProgress, ScanPhase } from '../scanner/types';
import { runScan, ProgressCallback } from '../scanner/ScanEngine';
import { Language, setLanguage as setI18nLanguage, getLanguage } from '../i18n';

interface ScanContextType {
  results: ScanResults | null;
  progress: ScanProgress | null;
  isScanning: boolean;
  error: string | null;
  language: Language;
  startScan: (quickMode: boolean) => Promise<void>;
  clearResults: () => void;
  changeLanguage: (lang: Language) => void;
}

const ScanCtx = createContext<ScanContextType | null>(null);

export function ScanProvider({ children }: { children: ReactNode }) {
  const [results, setResults] = useState<ScanResults | null>(null);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [language, setLang] = useState<Language>(getLanguage());

  const startScan = useCallback(async (quickMode: boolean) => {
    setIsScanning(true);
    setError(null);
    setResults(null);
    setProgress({ phase: 'idle', phaseIndex: 0, totalPhases: quickMode ? 5 : 7, message: '' });

    try {
      const scanResults = await runScan(quickMode, (prog) => {
        setProgress(prog);
      });
      setResults(scanResults);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsScanning(false);
    }
  }, []);

  const clearResults = useCallback(() => {
    setResults(null);
    setProgress(null);
    setError(null);
  }, []);

  const changeLanguage = useCallback((lang: Language) => {
    setI18nLanguage(lang);
    setLang(lang);
  }, []);

  return (
    <ScanCtx.Provider value={{
      results, progress, isScanning, error, language,
      startScan, clearResults, changeLanguage,
    }}>
      {children}
    </ScanCtx.Provider>
  );
}

export function useScan(): ScanContextType {
  const ctx = useContext(ScanCtx);
  if (!ctx) throw new Error('useScan must be used within ScanProvider');
  return ctx;
}
