import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, 
  Search, 
  AlertTriangle, 
  CheckCircle, 
  Info, 
  Globe, 
  Lock, 
  Cpu, 
  Terminal,
  ExternalLink,
  ChevronRight,
  Activity,
  Zap,
  RefreshCcw,
  MousePointer2,
  CalendarDays,
  User,
  Bell,
  Trash2,
  Camera,
  Upload,
  Download,
  QrCode,
  Plus,
  MessageSquare
} from 'lucide-react';
import html2canvas from 'html2canvas';
import { Html5Qrcode } from 'html5-qrcode';
import { motion, AnimatePresence } from 'motion/react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useAuth } from './components/AuthProvider';
import { ScanHistory } from './components/ScanHistory';
import { 
  auth, 
  db, 
  collection, 
  addDoc, 
  query, 
  where, 
  onSnapshot, 
  deleteDoc, 
  doc, 
  serverTimestamp,
  getDocs,
  handleFirestoreError,
  OperationType
} from './lib/firebase';
// Sidecar logic removed duplicate imports

// Helper for tailwind classes
function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

function getDomainAge(creationDate: string | undefined) {
  if (!creationDate) return null;
  try {
    const created = new Date(creationDate);
    if (isNaN(created.getTime())) return null;
    const now = new Date();
    const diffTime = now.getTime() - created.getTime();
    const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));
    
    if (diffDays < 0) return 'Just registered';
    if (diffDays < 30) return `${diffDays}d old`;
    if (diffDays < 365) return `${Math.floor(diffDays / 30)}mo old`;
    const years = Math.floor(diffDays / 365);
    return `${years}y old`;
  } catch (e) {
    return null;
  }
}

interface AnalysisResult {
  threatScore: number;
  classification: 'Safe' | 'Suspicious' | 'Phishing' | 'Malicious';
  explanation: string;
  recommendation: string;
  riskIndicators: string[];
  type?: 'url' | 'ip' | 'email' | 'domain' | 'keyword' | 'phone' | 'message';
  target?: string;
  technicalSummary: {
    dns: string;
    ssl: string;
    whois: string;
    threatIntel: string;
  };
  raw?: {
    dns: any;
    ssl: any;
    ct: any;
    whois: any;
    heuristics: any;
  };
}

function getGaugeColor(score: number) {
  if (score < 30) return 'text-[#39FF14]';
  if (score < 60) return 'text-amber-500';
  if (score < 80) return 'text-orange-500';
  return 'text-red-500';
}

function ThreatGauge({ score }: { score: number }) {
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="relative flex items-center justify-center">
      <svg width="100" height="100" className="transform -rotate-90 scale-110 md:scale-125">
        <circle
          cx="50"
          cy="50"
          r={radius}
          fill="transparent"
          stroke="currentColor"
          strokeWidth="6"
          className="text-[#39FF14]/5"
        />
        <motion.circle
          cx="50"
          cy="50"
          r={radius}
          fill="transparent"
          stroke="currentColor"
          strokeWidth="6"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 2, ease: "circOut" }}
          strokeLinecap="round"
          className={cn(
            score < 30 ? "stroke-[#39FF14]" :
            score < 60 ? "stroke-amber-500" :
            score < 80 ? "stroke-orange-500" : "stroke-red-500",
            "transition-colors duration-1000 shadow-[0_0_10px_rgba(57,255,20,0.5)]"
          )}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <motion.span 
          initial={{ opacity: 0, scale: 0.5 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.5 }}
          className={cn("text-3xl font-black italic tracking-tighter", getGaugeColor(score))}
        >
          {score}
        </motion.span>
        <span className="text-[7px] text-[#39FF14]/50 uppercase tracking-widest font-mono">THREAT.VAL</span>
      </div>
    </div>
  );
}

function ScanLines() {
  return (
    <div className="pointer-events-none fixed inset-0 z-[100] overflow-hidden">
      <div className="absolute inset-0 bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] bg-[length:100%_2px,3px_100%]" />
      <div className="animate-scanline absolute top-0 left-0 h-[100px] w-full bg-linear-to-b from-transparent via-[#39FF14]/5 to-transparent opacity-20" />
    </div>
  );
}

function GlobalMap() {
  return (
    <div className="glass-panel border-[#39FF14]/10 h-[220px] relative overflow-hidden group">
      <div className="absolute top-2 left-2 z-10">
        <h3 className="text-[10px] text-[#39FF14]/50 uppercase tracking-[0.2em] flex items-center gap-2">
          <Globe size={12} /> Global_Malware_Vectors
        </h3>
      </div>
      <svg className="w-full h-full opacity-20 grayscale invert-[0.8] brightness-125" viewBox="0 0 800 400">
        <path fill="currentColor" className="text-[#39FF14]" d="M150,150 L200,160 L220,140 L250,150 L260,180 Z M400,100 L450,110 L480,140 L440,160 Z M600,200 L650,220 L680,210 L700,240 Z" />
        <motion.circle 
          cx="200" cy="150" r="2" fill="#39FF14"
          animate={{ r: [2, 6, 2], opacity: [1, 0.2, 1] }}
          transition={{ duration: 2, repeat: Infinity }}
        />
        <motion.circle 
          cx="450" cy="130" r="2" fill="#39FF14"
          animate={{ r: [2, 6, 2], opacity: [1, 0.2, 1] }}
          transition={{ duration: 2, delay: 0.5, repeat: Infinity }}
        />
         <motion.circle 
          cx="650" cy="220" r="2" fill="#39FF14"
          animate={{ r: [2, 6, 2], opacity: [1, 0.2, 1] }}
          transition={{ duration: 2, delay: 1, repeat: Infinity }}
        />
        {/* Animated lines */}
        <motion.path 
          d="M200,150 Q325,140 450,130" 
          fill="none" 
          stroke="#39FF14" 
          strokeWidth="0.5" 
          strokeDasharray="4 4"
          animate={{ strokeDashoffset: [0, -20] }}
          transition={{ duration: 5, repeat: Infinity, ease: "linear" }}
        />
        <motion.path 
          d="M450,130 Q550,175 650,220" 
          fill="none" 
          stroke="#39FF14" 
          strokeWidth="0.5" 
          strokeDasharray="4 4"
          animate={{ strokeDashoffset: [0, -20] }}
          transition={{ duration: 4, repeat: Infinity, ease: "linear" }}
        />
      </svg>
      <div className="absolute bottom-2 right-2 flex flex-col items-end">
        <div className="flex gap-1">
          <span className="w-1 h-1 bg-[#39FF14] animate-ping" />
          <p className="text-[8px] uppercase tracking-tighter opacity-50">Active_Link_Established</p>
        </div>
        <p className="text-[9px] font-bold">NODE_ALPHA_7: ONLINE</p>
      </div>
    </div>
  );
}

function IntelFeed() {
  const [news, setNews] = useState([
    "CRITICAL: Zero-day exploit detected in major email provider...",
    "ADVISORY: Massive phishing campaign targeting financial sector identified.",
    "INFO: Global botnet activity decreased by 12% in the last 24h.",
    "WARN: New ransomware variant 'VoidHex' spreading via infected plugins.",
    "UPDATE: Core threat database updated with 12,402 new signatures."
  ]);

  useEffect(() => {
    const interval = setInterval(() => {
      setNews(prev => [...prev.slice(1), prev[0]]);
    }, 4000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="glass-panel border-[#39FF14]/10 bg-black/80 overflow-hidden h-12 flex items-center relative">
      <div className="bg-[#39FF14] text-black px-3 h-full flex items-center text-[10px] font-black uppercase tracking-widest z-10 shadow-[0_0_15px_rgba(57,255,20,0.3)]">
        LIVE_INTEL_FEED
      </div>
      <div className="flex-1 px-4 overflow-hidden">
        <AnimatePresence mode="wait">
          <motion.p 
            key={news[0]}
            initial={{ y: 20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: -20, opacity: 0 }}
            className="text-[11px] text-[#39FF14] font-bold truncate"
          >
            {news[0]}
          </motion.p>
        </AnimatePresence>
      </div>
    </div>
  );
}

function MatrixEffect() {
  return (
    <div className="glass-panel border-[#39FF14]/10 h-32 relative overflow-hidden flex flex-col items-center justify-center group">
       <div className="absolute inset-0 opacity-20 pointer-events-none grid grid-cols-12 gap-1 px-2">
          {Array.from({ length: 12 }).map((_, i) => (
             <motion.div 
               key={i} 
               className="text-[8px] flex flex-col"
               animate={{ y: [-100, 100] }}
               transition={{ duration: Math.random() * 5 + 3, repeat: Infinity, ease: "linear" }}
             >
                {Array.from({ length: 20 }).map((_, j) => (
                   <span key={j}>{Math.random() > 0.5 ? '1' : '0'}</span>
                ))}
             </motion.div>
          ))}
       </div>
       <p className="text-[10px] text-[#39FF14]/50 uppercase tracking-widest z-10">Neural_Core_Active</p>
       <div className="flex gap-4 mt-2 z-10">
          <div className="text-center">
             <p className="text-[12px] font-black">2.4 TB/s</p>
             <p className="text-[7px] opacity-50 uppercase">Throughput</p>
          </div>
          <div className="text-center">
             <p className="text-[12px] font-black text-amber-500">INIT</p>
             <p className="text-[7px] opacity-50 uppercase">Sequence</p>
          </div>
       </div>
    </div>
  );
}

function KeywordMonitor() {
  const { user, login } = useAuth();
  const [subscriptions, setSubscriptions] = useState<any[]>([]);
  const [newKeyword, setNewKeyword] = useState('');
  const [isAdding, setIsAdding] = useState(false);

  useEffect(() => {
    if (!user) {
      setSubscriptions([]);
      return;
    }

    const q = query(
      collection(db, 'subscriptions'), 
      where('userId', '==', user.uid)
    );

    return onSnapshot(q, (snapshot) => {
      const subs = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
      setSubscriptions(subs);
    }, (error) => {
      handleFirestoreError(error, OperationType.LIST, 'subscriptions');
    });
  }, [user]);

  const handleAddSubscription = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user || !newKeyword.trim() || isAdding) return;

    setIsAdding(true);
    try {
      await addDoc(collection(db, 'subscriptions'), {
        userId: user.uid,
        keyword: newKeyword.trim(),
        createdAt: serverTimestamp()
      });
      setNewKeyword('');
    } catch (error) {
      console.error('Failed to add subscription', error);
    } finally {
      setIsAdding(false);
    }
  };

  const handleDeleteSubscription = async (id: string) => {
    try {
      await deleteDoc(doc(db, 'subscriptions', id));
    } catch (error) {
      console.error('Failed to delete subscription', error);
    }
  };

  if (!user) {
    return (
      <section className="glass-panel border-[#39FF14]/20 p-5 space-y-4">
        <div className="flex justify-between items-center">
          <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-[#39FF14] flex items-center gap-2">
            <Activity size={12} className="text-amber-500" /> KEYWORD_WATCH
          </h3>
        </div>
        <div className="flex flex-col items-center justify-center py-8 space-y-3 border border-dashed border-[#39FF14]/10 bg-black/40">
           <Lock size={24} className="opacity-20" />
           <p className="text-[10px] opacity-40 uppercase tracking-widest text-center">Login to monitor keywords</p>
           <button 
             onClick={login}
             className="px-4 py-2 bg-[#39FF14]/10 border border-[#39FF14]/30 text-[#39FF14] text-[10px] font-black uppercase hover:bg-[#39FF14]/20 transition-all"
           >
             AUTH_INIT
           </button>
        </div>
      </section>
    );
  }

  return (
    <section className="glass-panel border-[#39FF14]/20 p-5 space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-[#39FF14] flex items-center gap-2">
          <Activity size={12} className="text-amber-500" /> KEYWORD_WATCH
        </h3>
        <span className="text-[8px] opacity-30 uppercase tracking-widest">REALTIME_SYNC</span>
      </div>

      <form onSubmit={handleAddSubscription} className="flex gap-2">
        <input 
          type="text"
          value={newKeyword}
          onChange={(e) => setNewKeyword(e.target.value)}
          placeholder="MONITORING_KEYWORD..."
          className="flex-1 bg-black border border-[#39FF14]/20 px-3 py-2 text-[10px] focus:outline-none focus:border-[#39FF14] placeholder:opacity-20"
        />
        <button 
          disabled={!newKeyword.trim() || isAdding}
          className="px-3 py-2 bg-[#39FF14] text-black text-[10px] font-black disabled:opacity-20 transition-all hover:scale-105 active:scale-95"
        >
          <Plus size={14} />
        </button>
      </form>

      <div className="space-y-2 max-h-[160px] overflow-y-auto custom-scrollbar pr-2">
        {subscriptions.length > 0 ? subscriptions.map((k) => (
          <div key={k.id} className="flex items-center justify-between py-2 border-b border-[#39FF14]/5 last:border-0 group">
            <div className="flex items-center gap-2">
              <div className="w-1 h-3 bg-[#39FF14]" />
              <span className="text-[11px] font-bold text-[#39FF14]/80 group-hover:text-white transition-colors">{k.keyword}</span>
            </div>
            <button 
              onClick={() => handleDeleteSubscription(k.id)}
              className="text-red-500/30 hover:text-red-500 transition-colors"
            >
              <Trash2 size={12} />
            </button>
          </div>
        )) : (
          <p className="text-[9px] opacity-20 italic text-center py-4">No keywords monitored.</p>
        )}
      </div>
    </section>
  );
}

function AlertNotifications() {
  const { user } = useAuth();
  const [alerts, setAlerts] = useState<any[]>([]);

  useEffect(() => {
    if (!user) {
      setAlerts([]);
      return;
    }

    const q = query(
      collection(db, 'alerts'), 
      where('userId', '==', user.uid)
    );

    return onSnapshot(q, (snapshot) => {
      const newAlerts = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
      // Sort by timestamp descending
      newAlerts.sort((a: any, b: any) => (b.timestamp?.seconds || 0) - (a.timestamp?.seconds || 0));
      setAlerts(newAlerts);
    }, (error) => {
      handleFirestoreError(error, OperationType.LIST, 'alerts');
    });
  }, [user]);

  if (!user || alerts.length === 0) return null;

  return (
    <div className="fixed top-24 right-4 z-[90] w-72 space-y-2 pointer-events-none">
      <AnimatePresence>
        {alerts.slice(0, 3).map((alert, idx) => (
          <motion.div
            key={alert.id}
            initial={{ x: 300, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: 300, opacity: 0 }}
            className="pointer-events-auto glass-panel border-red-500/40 bg-black/90 p-4 shadow-xl border-l-4"
          >
            <div className="flex justify-between items-start mb-1">
              <div className="flex items-center gap-2">
                <Bell size={14} className="text-red-500 animate-pulse" />
                <span className="text-[9px] font-black uppercase text-red-500 tracking-[0.2em]">THREAT_ALERT</span>
              </div>
              <button 
                onClick={async () => {
                  try {
                    await deleteDoc(doc(db, 'alerts', alert.id));
                  } catch (e) { console.error(e); }
                }}
                className="text-white/20 hover:text-white"
              >
                <Trash2 size={10} />
              </button>
            </div>
            <p className="text-[11px] font-bold text-white mb-1">Match: {alert.keyword}</p>
            <p className="text-[9px] opacity-60 leading-tight mb-2">{alert.message}</p>
            <div className="flex justify-between items-center text-[8px]">
              <span className="opacity-30 uppercase">{new Date(alert.timestamp?.seconds * 1000).toLocaleTimeString()}</span>
              <span className="bg-red-500/10 px-1 border border-red-500/20 text-red-500">SCORE: {alert.threatScore}</span>
            </div>
          </motion.div>
        ))}
      </AnimatePresence>
      {alerts.length > 3 && (
        <p className="text-center text-[8px] opacity-40 uppercase tracking-widest">+ {alerts.length - 3} more alerts</p>
      )}
    </div>
  );
}

function PhoneModule({ result }: { result: AnalysisResult }) {
  if (result.type !== 'phone') return null;
  
  return (
    <motion.div 
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-panel border-emerald-500/20 p-6 space-y-6"
    >
      <div className="flex justify-between items-center">
        <h3 className="text-[12px] font-black uppercase tracking-[0.2em] text-emerald-400 flex items-center gap-2">
          <Activity size={14} className="text-emerald-500" /> TELEPHONY_INTEL_GATHERING
        </h3>
        <span className="text-[9px] opacity-30 tracking-widest font-mono">SOURCE: TEL_INTEL_NETWORK</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="space-y-4">
          <div className="flex flex-col">
            <span className="text-[9px] font-black opacity-40 uppercase tracking-widest mb-1">Target_Identity</span>
            <p className="text-2xl font-black text-emerald-400">{result.raw?.dns?.records?.target || 'N/A'}</p>
          </div>
          <div className="p-3 bg-black/40 border border-emerald-500/10 space-y-2">
            <div className="flex justify-between text-[10px]">
              <span className="opacity-40">CARRIER_INTEL</span>
              <span className="text-emerald-400 font-bold italic">ANALYZING...</span>
            </div>
            <div className="flex justify-between text-[10px]">
              <span className="opacity-40">LOCATION_PROBE</span>
              <span className="text-emerald-400 font-bold">NODE_LOCKED</span>
            </div>
          </div>
        </div>
        <div className="bg-emerald-500/5 border border-emerald-500/10 p-4">
          <p className="text-[10px] font-bold text-emerald-500/70 uppercase mb-2">Neural_Risk_Assessment</p>
          <p className="text-[11px] leading-relaxed text-[#39FF14]/80 italic">
            {result.technicalSummary.threatIntel || "Telephony pattern matching indicates normal operation profile. No historical smishing campaigns associated with this signature in current epoch."}
          </p>
        </div>
      </div>
    </motion.div>
  );
}

function MessageModule({ result }: { result: AnalysisResult }) {
  if (result.type !== 'message') return null;
  
  const extractedUrls = result.raw?.heuristics?.extractedUrls || [];

  return (
    <motion.div 
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-panel border-amber-500/20 p-6 space-y-6"
    >
      <div className="flex justify-between items-center">
        <h3 className="text-[12px] font-black uppercase tracking-[0.2em] text-amber-500 flex items-center gap-2">
          <MessageSquare size={14} className="text-amber-500" /> SEMANTIC_THREAT_AUDIT
        </h3>
        <span className="text-[9px] opacity-30 tracking-widest font-mono">SOURCE: HEURISTIC_CORE_ALPHA</span>
      </div>

      <div className="space-y-6">
        <div className="p-4 bg-black/60 border border-amber-500/10 relative overflow-hidden">
           <div className="absolute top-0 right-0 p-1 bg-amber-500/10 border-l border-b border-amber-500/20 text-[8px] text-amber-500 font-black">ORIGINAL_CONTENT</div>
           <p className="text-[12px] font-mono text-amber-500/80 leading-relaxed italic">
             "{result.raw?.dns?.records?.target || 'No message content recorded.'}"
           </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
           {extractedUrls.length > 0 && (
             <div className="lg:col-span-1 space-y-3">
                <p className="text-[9px] font-black opacity-40 uppercase tracking-widest">Extracted_Links</p>
                <div className="space-y-2">
                   {extractedUrls.map((url: string, i: number) => (
                      <div key={i} className="p-2 bg-black border border-amber-500/20 text-[9px] text-[#39FF14] flex items-center justify-between group">
                         <span className="truncate max-w-[150px]">{url}</span>
                         <button 
                           onClick={() => { (window as any).setUrl(url); (window as any).handleAnalyze(undefined, url); }}
                           className="opacity-0 group-hover:opacity-100 transition-opacity"
                         >
                            <ExternalLink size={10} />
                         </button>
                      </div>
                   ))}
                </div>
             </div>
           )}
           <div className={cn("space-y-3", extractedUrls.length > 0 ? "lg:col-span-2" : "lg:col-span-3")}>
              <p className="text-[9px] font-black opacity-40 uppercase tracking-widest">Heuristic_Analysis</p>
              <div className="bg-amber-500/5 border border-amber-500/10 p-4">
                 <p className="text-[11px] leading-relaxed text-amber-200/80 italic">
                    {result.explanation}
                 </p>
                 <div className="mt-4 flex flex-wrap gap-2">
                    {result.riskIndicators.map((risk, i) => (
                       <span key={i} className="text-[8px] bg-red-500/10 border border-red-500/20 px-2 py-0.5 text-red-400 uppercase font-black">
                          {risk}
                       </span>
                    ))}
                 </div>
              </div>
           </div>
        </div>
      </div>
    </motion.div>
  );
}

function QRScannerModule({ onScan }: { onScan: (decodedText: string) => void }) {
  const [isScanning, setIsScanning] = useState(false);
  const [hasError, setHasError] = useState<string | null>(null);
  const scannerRef = useRef<Html5Qrcode | null>(null);

  useEffect(() => {
    let isMounted = true;
    let timer: NodeJS.Timeout;

    if (isScanning) {
      const startScanner = async () => {
        // Small delay to ensure React has rendered the #qr-reader div
        timer = setTimeout(async () => {
          try {
            const element = document.getElementById("qr-reader");
            if (!element || !isMounted) return;

            if (scannerRef.current) {
              try {
                await scannerRef.current.stop();
              } catch (e) {
                // Ignore stop errors
              }
            }

            const scanner = new Html5Qrcode("qr-reader");
            scannerRef.current = scanner;

            const config = {
              fps: 10,
              qrbox: (viewfinderWidth: number, viewfinderHeight: number) => {
                const minEdgeSize = Math.min(viewfinderWidth, viewfinderHeight);
                const qrboxSize = Math.floor(minEdgeSize * 0.7);
                return {
                  width: qrboxSize,
                  height: qrboxSize
                };
              },
              aspectRatio: 1.0
            };

            await scanner.start(
              { facingMode: "environment" },
              config,
              (decodedText) => {
                onScan(decodedText);
                stopScanning();
              },
              () => {
                // Ignore standard scanning errors
              }
            );
            
            if (isMounted) setHasError(null);
          } catch (err: any) {
            console.error("Scanner start error:", err);
            if (!isMounted) return;
            
            let msg = "CAMERA_ACCESS_DENIED OR HARDWARE_ERROR";
            const errStr = String(err);
            if (errStr.includes("NotAllowedError")) msg = "PERMISSION_DENIED: Enable Camera or Open App in New Tab";
            if (errStr.includes("NotFoundError")) msg = "HARDWARE_NOT_FOUND: No Camera Detected";
            if (errStr.includes("NotReadableError")) msg = "CAMERA_IN_USE: Close other apps using camera";
            
            setHasError(msg);
            setIsScanning(false);
          }
        }, 150);
      };

      startScanner();
    }

    return () => {
      isMounted = false;
      clearTimeout(timer);
      if (scannerRef.current) {
        // We don't await here as it's a cleanup, but we try to stop if it was running
        const stopIfRunning = async () => {
          try {
            // Note: stop() can only be called if it was successfully started
            await scannerRef.current?.stop();
            scannerRef.current = null;
          } catch (e) {
            // Silent cleanup
          }
        };
        stopIfRunning();
      }
    };
  }, [isScanning]);

  const stopScanning = async () => {
    if (scannerRef.current) {
      try {
        const state = scannerRef.current.getState();
        if (state === 2) {
          await scannerRef.current.stop();
        }
        scannerRef.current = null;
      } catch (e) {
        console.error("Stop error:", e);
      }
    }
    setIsScanning(false);
  };

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const dummyId = "qr-reader-file-dummy";
    let dummy = document.getElementById(dummyId);
    if (!dummy) {
      dummy = document.createElement("div");
      dummy.id = dummyId;
      dummy.style.display = "none";
      document.body.appendChild(dummy);
    }

    const scanner = new Html5Qrcode(dummyId);
    try {
      const decodedText = await scanner.scanFile(file, true);
      onScan(decodedText);
      setHasError(null);
    } catch (err) {
      console.error("File scan error:", err);
      setHasError("DECODE_FAULT: QR Signature could not be extracted from provided image.");
    }
  };

  return (
    <section className="glass-panel border-cyan-500/30 bg-black/80 p-4 relative overflow-hidden group">
      <div className="absolute top-0 right-0 w-16 h-16 bg-cyan-500/5 -rotate-45 translate-x-8 -translate-y-8" />
      <div className="flex items-center justify-between mb-4">
         <h2 className="text-[10px] text-cyan-400 font-bold uppercase tracking-[0.3em] flex items-center gap-2">
            <QrCode size={12} /> QR_INTEL_EXTRACTOR
         </h2>
         <div className="flex gap-1">
            <div className="w-1.5 h-1.5 bg-cyan-500/10 border border-cyan-500/20" />
            <div className={cn("w-1.5 h-1.5 bg-cyan-500 animate-pulse", isScanning && "bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.5)]")} />
         </div>
      </div>
      
      <div className="space-y-4">
        {hasError && (
          <div className="bg-red-500/10 border border-red-500/30 p-2 mb-2 space-y-2">
             <div className="flex items-start gap-2">
                <AlertTriangle size={14} className="text-red-500 shrink-0" />
                <p className="text-[8px] text-red-500 font-bold uppercase italic leading-tight">{hasError}</p>
             </div>
             <div className="flex flex-col gap-1 pl-5">
               <a 
                 href={window.location.href} 
                 target="_blank" 
                 rel="noopener noreferrer"
                 className="text-[7px] text-cyan-400 underline uppercase tracking-widest block hover:text-cyan-300"
               >
                 {"->"} Open App in New Tab to fix Permissions
               </a>
               <label className="text-[7px] text-cyan-400 underline uppercase tracking-widest cursor-pointer hover:text-cyan-300">
                 {"->"} Or Process Static Image File
                 <input type="file" accept="image/*" className="hidden" onChange={handleFileUpload} />
               </label>
             </div>
          </div>
        )}
        {!isScanning ? (
          <div className="flex flex-col gap-2">
            <button 
              onClick={() => {
                setHasError(null);
                setIsScanning(true);
              }}
              className="w-full bg-cyan-600/20 border border-cyan-600/50 text-cyan-400 font-black py-8 flex flex-col items-center justify-center gap-3 hover:bg-cyan-600/30 transition-all group"
            >
               <Camera size={32} className="group-hover:scale-110 transition-transform" />
               <div className="text-center">
                  <span className="text-[10px] block tracking-[0.2em]">INITIALIZE_CAM_PROBE</span>
                  <span className="text-[7px] opacity-40 block mt-1 uppercase tracking-widest italic">Target: Real-world QR Signatures</span>
               </div>
            </button>
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-cyan-500/10" />
              </div>
              <div className="relative flex justify-center text-[7px] uppercase">
                <span className="bg-black px-2 text-cyan-500/30 tracking-widest italic">Alternative Mode</span>
              </div>
            </div>
            <label className="w-full bg-black border border-cyan-500/20 text-cyan-500/60 font-bold py-2 flex items-center justify-center gap-2 text-[8px] uppercase tracking-widest cursor-pointer hover:bg-cyan-500/5 transition-all">
              <Upload size={12} /> UPLOAD_QR_STATIC_FRAME
              <input type="file" accept="image/*" className="hidden" onChange={handleFileUpload} />
            </label>
          </div>
        ) : (
          <div className="space-y-4">
            <div id="qr-reader" className="w-full aspect-square border border-cyan-500/30 bg-black overflow-hidden relative rounded-sm" />
            <button 
              onClick={stopScanning}
              className="w-full bg-red-600/10 border border-red-600/50 text-red-500 font-black py-2 text-[8px] uppercase tracking-widest hover:bg-red-600/20 transition-all"
            >
              ABORT_CAM_SYNC
            </button>
          </div>
        )}
        
        <div className="flex justify-between items-center text-[7px] opacity-30 pt-2 border-t border-cyan-500/10">
           <span>PROTOCOL: OPTICAL_DECODE</span>
           <span>SYNC_STATE: {isScanning ? 'STREAMING' : 'IDLE'}</span>
        </div>
      </div>
    </section>
  );
}

function VisualEvidenceModule({ result }: { result: AnalysisResult }) {
  if (result.type !== 'url' && result.type !== 'domain') return null;
  const targetUrl = result.target || (result.type === 'url' ? 'URL' : 'DOMAIN');
  const screenshotUrl = `https://s.wordpress.com/mshots/v1/${encodeURIComponent(targetUrl)}?w=1280`;

  return (
    <motion.div 
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-panel border-[#39FF14]/20 p-5 space-y-4"
    >
      <div className="flex justify-between items-center">
        <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-[#39FF14] flex items-center gap-2">
          <Camera size={12} className="text-blue-400" /> LIVE_VISUAL_EVIDENCE
        </h3>
        <span className="text-[8px] opacity-30 italic">RENDER_ENGINE: MSHOTS_V1</span>
      </div>
      <div className="relative group overflow-hidden border border-[#39FF14]/10 bg-black aspect-video flex items-center justify-center">
         <img 
           src={screenshotUrl} 
           alt="Target Preview" 
           className="w-full h-full object-cover opacity-60 group-hover:opacity-100 transition-opacity duration-700" 
           referrerPolicy="no-referrer"
         />
         <div className="absolute inset-0 bg-gradient-to-t from-black/80 via-transparent to-transparent pointer-events-none" />
         <div className="absolute bottom-2 left-2 flex items-center gap-2">
            <div className="w-1.5 h-1.5 bg-red-500 rounded-full animate-pulse" />
            <span className="text-[8px] font-black uppercase tracking-widest text-[#39FF14]/60">LIVE_CAPTURE_BUFFER</span>
         </div>
         <a 
           href={targetUrl} 
           target="_blank" 
           rel="noopener noreferrer"
           className="absolute top-2 right-2 p-1.5 bg-black/80 border border-[#39FF14]/20 text-[#39FF14] opacity-0 group-hover:opacity-100 transition-opacity"
         >
           <ExternalLink size={10} />
         </a>
      </div>
      <p className="text-[8px] opacity-40 uppercase leading-tight">
        Visual signature captured at epoch {new Date().toLocaleTimeString()}. Cross-referencing pixel similarity with known phishing templates.
      </p>
    </motion.div>
  );
}

function ExtensionModule() {
  return (
    <section className="glass-panel border-purple-500/30 bg-black/80 p-4 relative overflow-hidden group">
      <div className="absolute top-0 right-0 w-16 h-16 bg-purple-500/5 -rotate-45 translate-x-8 -translate-y-8" />
      <div className="flex items-center justify-between mb-4">
         <h2 className="text-[10px] text-purple-400 font-bold uppercase tracking-[0.3em] flex items-center gap-2">
            <Download size={12} /> BROWSER_EXTENSION
         </h2>
         <div className="flex gap-1">
            <div className="w-1.5 h-1.5 bg-purple-500/10 border border-purple-500/20" />
            <div className="w-1.5 h-1.5 bg-purple-500 animate-pulse" />
         </div>
      </div>
      
      <div className="space-y-4">
        <div className="p-3 bg-purple-500/5 border border-purple-500/10">
           <p className="text-[10px] text-purple-200/60 leading-relaxed italic">
             Scale your intelligence gathering. Perform real-time scans directly from your browser toolbar.
           </p>
        </div>
        
        <div className="flex flex-col gap-2">
          <div className="text-[8px] text-purple-400/40 uppercase tracking-widest font-mono">
            DEPLOYMENT_FILES:
          </div>
          <div className="grid grid-cols-2 gap-2">
             <div className="text-[9px] bg-black border border-purple-500/20 px-2 py-1 flex items-center gap-2 opacity-60">
                <div className="w-1 h-1 bg-purple-500" /> manifest.json
             </div>
             <div className="text-[9px] bg-black border border-purple-500/20 px-2 py-1 flex items-center gap-2 opacity-60">
                <div className="w-1 h-1 bg-purple-500" /> popup.html
             </div>
             <div className="text-[9px] bg-black border border-purple-500/20 px-2 py-1 flex items-center gap-2 opacity-60">
                <div className="w-1 h-1 bg-purple-500" /> popup.js
             </div>
             <div className="text-[9px] bg-black border border-purple-500/20 px-2 py-1 flex items-center gap-2 opacity-60">
                <div className="w-1 h-1 bg-purple-500" /> popup.css
             </div>
          </div>
        </div>

        <button 
          onClick={() => window.open('/extension/README.md', '_blank')}
          className="w-full bg-purple-600/20 border border-purple-600/50 text-purple-400 font-black py-2 rounded-none flex items-center justify-center gap-2 hover:bg-purple-600/30 active:scale-[0.98] transition-all group uppercase tracking-widest text-[9px]"
        >
          <ExternalLink size={12} />
          VIEW_EXTENSION_GUIDE
        </button>

        <div className="text-center text-[7px] opacity-30 italic">
          COMPATIBILITY: CHROMIUM_ENGINE_88+
        </div>
      </div>
    </section>
  );
}

function ReputationModule({ result }: { result: AnalysisResult }) {
  if (result.type === 'keyword' || result.type === 'phone' || result.type === 'message') return null;

  const reps = result.raw?.dns?.reputation || [];
  const ips = result.raw?.dns?.ips || [];
  const neighbors = result.raw?.dns?.records?.neighborDomains || [];
  const reverse = result.raw?.dns?.reverse || [];

  return (
    <motion.div 
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.1 }}
      className="glass-panel border-[#39FF14]/20 p-6 space-y-6"
    >
      <div className="flex justify-between items-center">
        <h3 className="text-[12px] font-black uppercase tracking-[0.2em] text-[#39FF14] flex items-center gap-2">
          <Shield size={14} className="text-red-500" /> REPUTATION_&_BLACKLIST_AUDIT
        </h3>
        <span className="text-[9px] opacity-30 tracking-widest font-mono">SOURCE: DNSBL_GLOBAL_CLUSTER</span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* IP REPUTATION */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-[9px] font-black opacity-40 uppercase tracking-widest">Active_IP_Endpoints</p>
            <span className="text-[9px] text-[#39FF14]/50 font-mono">{ips.length} DETECTED</span>
          </div>
          <div className="space-y-2 max-h-[160px] overflow-y-auto custom-scrollbar pr-2">
            {ips.length > 0 ? ips.map((ip: string) => {
              const ipReps = reps.filter((r: any) => r.ip === ip);
              const ipReverse = reverse?.[0];
              return (
                <div key={ip} className="bg-black/40 border border-[#39FF14]/10 p-3 flex justify-between items-center group hover:border-[#39FF14]/30 transition-all">
                  <div className="flex flex-col">
                    <span className="text-[11px] font-bold text-[#39FF14] tracking-tight">{ip}</span>
                    {ipReverse && (
                      <span className="text-[8px] text-blue-400 opacity-60 font-mono truncate max-w-[150px]">PTR: {ipReverse}</span>
                    )}
                    {ipReps.length > 0 ? (
                      <div className="flex flex-wrap gap-1 mt-1">
                        {ipReps.map((r: any, idx: number) => (
                          <span key={idx} className="text-[8px] text-red-400 flex items-center gap-1 bg-red-400/5 px-1 py-0.5">
                            <AlertTriangle size={8} /> {r.provider}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-[8px] text-emerald-500 opacity-60 flex items-center gap-1 mt-1">
                        <CheckCircle size={8} /> NO_LISTINGS_FOUND
                      </span>
                    )}
                  </div>
                  <div className={cn(
                    "px-2 py-0.5 text-[8px] font-black uppercase border",
                    ipReps.length > 0 ? "border-red-500/50 text-red-500 bg-red-500/10" : "border-emerald-500/50 text-emerald-500 bg-emerald-500/10"
                  )}>
                    {ipReps.length > 0 ? "BLACKLISTED" : "AUTHORIZED"}
                  </div>
                </div>
              );
            }) : (
              <p className="text-[10px] opacity-30 italic p-4 text-center border border-dashed border-[#39FF14]/10">No IP endpoints detected.</p>
            )}
          </div>
        </div>

        {/* NEIGHBOR DOMAINS */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-[9px] font-black opacity-40 uppercase tracking-widest">Shared_Infrastructure</p>
            <span className="text-[9px] text-blue-400/50 font-mono">CLUSTER_NEIGHBORS</span>
          </div>
          <div className="bg-black/40 border border-[#39FF14]/10 p-3 h-[160px] overflow-y-auto custom-scrollbar">
            {neighbors.length > 0 ? (
              <div className="grid grid-cols-1 gap-2">
                {neighbors.map((domain: string, idx: number) => (
                  <div key={idx} className="flex items-center justify-between text-[10px] border-b border-[#39FF14]/5 pb-1.5 last:border-0 hover:bg-white/[0.02] px-1 transition-colors">
                    <div className="flex items-center gap-2 text-[#39FF14]/70">
                      <ChevronRight size={10} className="opacity-30" />
                      <span className="truncate max-w-[180px]">{domain}</span>
                    </div>
                    <span className="text-[8px] opacity-20 font-mono uppercase">SHARED_IP</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="h-full flex flex-col items-center justify-center space-y-2 opacity-30">
                 <Globe size={24} strokeWidth={1} />
                 <p className="text-[10px] italic">No neighbor domains detected on this cluster.</p>
              </div>
            )}
          </div>
          <p className="text-[7px] opacity-30 italic leading-tight">
             * This audit checks for other domains hosted on the same IP cluster. A high density of phishing neighbors indicates a malicious hosting environment.
          </p>
        </div>
      </div>
    </motion.div>
  );
}

function VulnerabilityModule({ result }: { result: AnalysisResult }) {
  if (result.type === 'keyword' || result.type === 'phone' || result.type === 'message') return null;
  const vulns = result.raw?.dns?.vulnerabilities || [];
  if (vulns.length === 0) return null;

  return (
    <motion.div 
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.2 }}
      className="glass-panel border-orange-500/20 p-6 space-y-4"
    >
      <div className="flex justify-between items-center">
        <h3 className="text-[12px] font-black uppercase tracking-[0.2em] text-orange-500 flex items-center gap-2">
          <Terminal size={14} /> EXPLOIT_&_SERVICE_SURFACE
        </h3>
        <span className="text-[8px] opacity-30 uppercase tracking-widest font-mono">SOURCE: INTERNET_DB / SHODAN</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {vulns.map((v: any, idx: number) => (
          <div key={idx} className="bg-black/60 border border-orange-500/10 p-4 space-y-4">
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-black tracking-tight bg-orange-500/10 px-2 py-0.5 border border-orange-500/20">{v.ip}</span>
              <div className="h-px flex-1 bg-orange-500/10" />
            </div>

            <div className="space-y-3">
              <div>
                <p className="text-[9px] font-black opacity-40 uppercase mb-2">Open_Ports</p>
                <div className="flex flex-wrap gap-1">
                  {v.ports?.length > 0 ? v.ports.map((p: number) => (
                    <span key={p} className="px-2 py-0.5 bg-black border border-emerald-500/30 text-emerald-500 text-[10px] font-mono">
                      {p}
                    </span>
                  )) : <span className="text-[9px] opacity-20">NO_PUBLIC_PORTS_DETECTED</span>}
                </div>
              </div>

              <div>
                <p className="text-[9px] font-black opacity-40 uppercase mb-2 text-red-400">CVE_Vulnerabilities</p>
                <div className="space-y-1">
                  {v.cves?.length > 0 ? v.cves.slice(0, 5).map((cve: string) => (
                     <div key={cve} className="flex items-center gap-2 text-[10px] text-red-400/80 bg-red-500/5 px-2 py-1 border border-red-500/10">
                        <AlertTriangle size={10} />
                        <span className="font-mono">{cve}</span>
                     </div>
                  )) : <div className="text-[9px] opacity-20 italic">NO_KNOWN_CVES_FOUND</div>}
                  {v.cves?.length > 5 && (
                    <p className="text-[8px] opacity-30 text-center">+{v.cves.length - 5} MORE RECORDS</p>
                  )}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </motion.div>
  );
}

export default function App() {
  const { user, login, logout: handleLogout, isAdmin } = useAuth();
  const dashboardRef = useRef<HTMLDivElement>(null);
  const [activeTab, setActiveTab] = useState<'scan' | 'history'>('scan');

  const captureReport = async () => {
    if (!dashboardRef.current) return;
    addLog("INITIALIZING_SCREENSHOT_BUFFER...");
    try {
      const canvas = await html2canvas(dashboardRef.current, {
        backgroundColor: '#000000',
        scale: 2,
        logging: false,
        useCORS: true
      });
      const dataUrl = canvas.toDataURL('image/png');
      const link = document.createElement('a');
      link.download = `phish-intel-report-${Date.now()}.png`;
      link.href = dataUrl;
      link.click();
      addLog("REPORT_CAPTURE_SUCCESS. EXPORTED_TO_LOCAL.");
    } catch (err) {
      console.error(err);
      addLog("REPORT_CAPTURE_CRITICAL_FAILURE.");
    }
  };

  const [url, setUrl] = useState('');
  const [ipAddress, setIpAddress] = useState('');
  const [emailAddress, setEmailAddress] = useState('');
  const [domainName, setDomainName] = useState('');
  const [phoneAddress, setPhoneAddress] = useState('');
  const [messageContent, setMessageContent] = useState('');
  const [urlError, setUrlError] = useState<string | null>(null);
  const [ipError, setIpError] = useState<string | null>(null);
  const [emailError, setIpEmailError] = useState<string | null>(null);
  const [domainError, setDomainError] = useState<string | null>(null);
  const [phoneError, setPhoneError] = useState<string | null>(null);
  const [messageError, setMessageError] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const scrollRef = useRef<HTMLDivElement>(null);

  const scannerModes = [
    { id: 'url', label: 'URL_SCAN', icon: ExternalLink, example: 'https://paypal-secure-login.com' },
    { id: 'ip', label: 'IP_SCAN', icon: Terminal, example: '185.156.174.20' },
    { id: 'email', label: 'EMAIL_SCAN', icon: Zap, example: 'support@secure-update.net' },
    { id: 'phone', label: 'PHONE_PROBE', icon: Activity, example: '+15550199' },
    { id: 'message', label: 'SMS_AUDIT', icon: MessageSquare, example: 'Verify your account at: http://bit.ly/secure-login' },
    { id: 'domain', label: 'DOMAIN_SCAN', icon: Globe, example: 'apple-id.plist-verify.com' },
    { id: 'keyword', label: 'KEY_SCAN', icon: Search, example: 'VoidHex' },
    { id: 'qr', label: 'QR_DECODE', icon: QrCode, example: 'https://ais-dev.com' }
  ];

  const addLog = (msg: string) => {
    setLogs(prev => [...prev.slice(-30), `[${new Date().toLocaleTimeString()}] ${msg}`]);
  };

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  // Handle auto-scan if URL is in query params or if it's an extension popup
  useEffect(() => {
    const initScan = async () => {
      // 1. Check query params first
      const params = new URLSearchParams(window.location.search);
      const queryUrl = params.get('url');
      
      if (queryUrl) {
        setUrl(queryUrl);
        handleAnalyze(undefined, queryUrl);
        return;
      }

      // 2. Try to get current tab if in extension environment
      // @ts-ignore
      if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
        try {
          // @ts-ignore
          chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            const tab = tabs[0];
            if (tab?.url && (tab.url.startsWith('http') || tab.url.startsWith('https'))) {
              setUrl(tab.url);
              handleAnalyze(undefined, tab.url);
            }
          });
        } catch (e) {
          console.error('Failed to get chrome tab', e);
        }
      }
    };

    initScan();
  }, []);

  const validateUrl = (input: string) => {
    if (!input) {
      setUrlError(null);
      return false;
    }

    // Message Check (Natural language, spaces, long text)
    if (input.split(' ').length > 2 || (input.length > 30 && input.includes(' '))) {
        setUrlError(null);
        return true;
    }

    // IP Check
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(input)) {
        setUrlError(null);
        return true;
    }

    // Phone Check
    if (/^\+?[\d\s-]{7,15}$/.test(input)) {
        setUrlError(null);
        return true;
    }

    // Email Check
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input)) {
        setUrlError(null);
        return true;
    }

    // Keyword Check (simple string, no dots, no spaces at this point)
    if (input.length > 0 && !input.includes('.') && !input.includes('/') && !input.includes('@') && !input.includes(' ')) {
        setUrlError(null);
        return true;
    }

    // Deep Link Check (e.g., upi://, tel://, mailto:, etc.)
    // Matches standard URI schemes: scheme:path
    if (/^[a-z][a-z0-9+.-]*:/i.test(input) && !input.startsWith('http') && !input.startsWith('https')) {
        setUrlError(null);
        return true;
    }

    try {
      // Allow domain-only input (autocorrect to https for validation)
      const inputToTest = input.includes('://') ? input : `https://${input}`;
      const parsed = new URL(inputToTest);
      
      const hostParts = parsed.hostname.split('.');
      if (hostParts.length < 2) {
        // If it still doesn't look like a URL but we didn't catch it as a keyword/phone
        // it might be a valid input for something else or just a keyword.
        // But for "URL" specifically, we want at least a dot in the hostname.
        if (input.includes('.') || input.includes('/')) {
           setUrlError('Invalid scope (e.g., domain.com)');
           return false;
        }
        setUrlError(null);
        return true;
      }

      if (input.includes('<') || input.includes('>')) {
        setUrlError('Invalid characters detected');
        return false;
      }

      setUrlError(null);
      return true;
    } catch (e) {
      setUrlError('INVALID_TARGET_STRUCTURE');
      return false;
    }
  };

  useEffect(() => {
    validateUrl(url);
  }, [url]);

  const validateIp = (input: string) => {
    if (!input) {
      setIpError(null);
      return false;
    }
    const isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(input);
    if (!isIp) {
      setIpError('INVALID_IPV4_ADDRESS');
      return false;
    }
    setIpError(null);
    return true;
  };

  useEffect(() => {
    validateIp(ipAddress);
  }, [ipAddress]);

  const validateEmail = (input: string) => {
    if (!input) {
      setIpEmailError(null);
      return false;
    }
    const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input);
    if (!isEmail) {
      setIpEmailError('INVALID_EMAIL_FORMAT');
      return false;
    }
    setIpEmailError(null);
    return true;
  };

  useEffect(() => {
    validateEmail(emailAddress);
  }, [emailAddress]);

  const validateDomain = (input: string) => {
    if (!input) {
      setDomainError(null);
      return false;
    }
    const isDomain = /^[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/.test(input) && !input.includes(' ');
    if (!isDomain) {
      setDomainError('INVALID_DOMAIN_NAMESPACE');
      return false;
    }
    setDomainError(null);
    return true;
  };

  useEffect(() => {
    validateDomain(domainName);
  }, [domainName]);

  const validatePhone = (input: string) => {
    if (!input) {
      setPhoneError(null);
      return false;
    }
    const isPhone = /^\+?[\d\s-]{7,15}$/.test(input);
    if (!isPhone) {
      setPhoneError('INVALID_PHONE_FORMAT');
      return false;
    }
    setPhoneError(null);
    return true;
  };

  useEffect(() => {
    validatePhone(phoneAddress);
  }, [phoneAddress]);

  const validateMessage = (input: string) => {
    if (!input) {
      setMessageError(null);
      return false;
    }
    if (input.length < 5) {
      setMessageError('CONTENT_TOO_SHORT');
      return false;
    }
    setMessageError(null);
    return true;
  };

  useEffect(() => {
    validateMessage(messageContent);
  }, [messageContent]);

  const handleAnalyze = async (e?: React.FormEvent, targetUrl?: string) => {
    if (e) e.preventDefault();
    const finalUrl = targetUrl || url;
    
    if (!finalUrl) return;
    
    // Final validation before execution
    if (!validateUrl(finalUrl)) {
      addLog("VALIDATION FAILURE: CANNOT PROCEED WITH MALFORMED TARGET.");
      return;
    }

    setIsAnalyzing(true);
    setResult(null);
    setAnalysisError(null);
    setLogs([]);
    
    const wait = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
    
    try {
      addLog(`INITIATING THREAT SCAN: ${finalUrl}`);
      await wait(400);
      addLog("RESOLVING DNS HIERARCHY...");
      await wait(500);
      addLog("EXTRACTING A & MX RECORDS...");
      await wait(300);
      addLog("PERFORMING SSL/TLS HANDSHAKE...");
      await wait(600);
      addLog("AUDITING DOMAIN AGE & WHOIS RECORDS...");
      await wait(400);
      addLog("SEARCHING CERTIFICATE TRANSPARENCY LOGS...");
      await wait(700);
      addLog("QUERYING LYZR THREAT INTELLIGENCE FEED...");
      await wait(400);
      addLog("SCANNING FOR KNOWN EXPLOITS (INTERNET_DB)...");
      
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: finalUrl })
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `SERVER_ERROR_${response.status}`);
      }

      const serverData = await response.json();
      addLog("SERVER_INTEL_GATHERING_COMPLETE.");
      
      const data = serverData as AnalysisResult;
      addLog("AI PROCESSING COMPLETE (SERVER_SIDE).");
      addLog(`CLASSIFICATION: ${data.classification} | SCORE: ${data.threatScore}`);
      setResult(data);

      // Save to Firestore if user is logged in
      if (user) {
        try {
          addLog("ARCHIVING_INTEL_REPORT_IN_CLOUD_STORAGE...");
          await addDoc(collection(db, 'scanReports'), {
            userId: user.uid,
            target: finalUrl,
            type: data.type || 'url',
            threatScore: data.threatScore,
            classification: data.classification,
            explanation: data.explanation,
            recommendation: data.recommendation,
            riskIndicators: data.riskIndicators,
            technicalSummary: data.technicalSummary,
            createdAt: serverTimestamp()
          });

          // Check for high threat score (> 70) and create an alert
          if (data.threatScore > 70) {
            addLog("!!! CRITICAL ALERT !!! HIGH THREAT SCORE DETECTED.");
            await addDoc(collection(db, 'alerts'), {
              userId: user.uid,
              keyword: "HIGH_THREAT",
              message: `Emergency: High threat signature detected for ${finalUrl}. Risk is critical.`,
              threatScore: data.threatScore,
              timestamp: serverTimestamp()
            });
          }

          // Check for keyword matches and create alerts
          if (data.threatScore > 40) {
            const subscriptionsSnap = await getDocs(query(collection(db, 'subscriptions'), where('userId', '==', user.uid)));
            const userSubscriptions = subscriptionsSnap.docs.map(d => d.data().keyword.toLowerCase());
            
            const fullText = `${data.explanation} ${data.riskIndicators.join(' ')} ${data.technicalSummary.dns} ${finalUrl}`.toLowerCase();
            
            for (const kw of userSubscriptions) {
              if (fullText.includes(kw)) {
                 addLog(`!!! ALERT !!! KEYWORD MATCH DETECTED: ${kw.toUpperCase()}`);
                 await addDoc(collection(db, 'alerts'), {
                   userId: user.uid,
                   keyword: kw.toUpperCase(),
                   message: `Monitored vector match detected in scan: ${finalUrl}`,
                   threatScore: data.threatScore,
                   timestamp: serverTimestamp()
                 });
              }
            }
          }
        } catch (dbErr) {
          console.error("Failed to archive report or process alerts:", dbErr);
          addLog("WARNING: PERSISTENCE_FAULT. Some real-time intelligence features may be limited.");
          handleFirestoreError(dbErr, OperationType.CREATE, 'scanReports');
        }
      }
    } catch (err: any) {
      console.error("ANALYSIS_PIPELINE_ERROR:", err);
      addLog(`CRITICAL FAILURE: ${err.message || 'Unknown protocol error'}`);
      setAnalysisError(err.message || "An unexpected error occurred during the scanning process.");
    } finally {
      setIsAnalyzing(false);
    }
  };

  const getStatusColor = (classification?: string) => {
    switch (classification) {
      case 'Safe': return 'text-emerald-400 border-[#39FF14]/30 bg-[#39FF14]/5';
      case 'Suspicious': return 'text-amber-400 border-amber-500/30 bg-amber-500/5';
      case 'Phishing': return 'text-orange-400 border-orange-500/30 bg-orange-500/5';
      case 'Malicious': return 'text-red-400 border-red-500/30 bg-red-500/5';
      default: return 'text-[#39FF14]/50 border-[#39FF14]/30 bg-[#39FF14]/5';
    }
  };

  return (
    <div className="min-h-screen bg-[#050505] text-[#39FF14] p-4 md:p-6 font-mono selection:bg-[#39FF14] selection:text-black">
      <ScanLines />
      {/* Header Rail */}
      <header className="flex items-center justify-between mb-8 border-b border-[#39FF14]/10 pb-4 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-32 h-full bg-linear-to-l from-[#39FF14]/5 to-transparent skew-x-12" />
        <div className="flex items-center gap-3">
          <div className="p-2 bg-[#39FF14] text-black rounded-none shadow-[0_0_15px_rgba(57,255,20,0.4)]">
            <Shield size={24} strokeWidth={2.5} />
          </div>
          <div>
            <h1 className="text-xl font-black tracking-tighter uppercase italic">Cyber Shield AI</h1>
            <p className="text-[10px] text-[#39FF14]/50 uppercase tracking-[0.4em] font-sans">Level_4_Threat_Analysis_Terminal</p>
          </div>
        </div>
        <div className="hidden md:flex items-center gap-6">
          {user ? (
            <div className="flex items-center gap-3 border-r border-[#39FF14]/10 pr-6">
               <div className="text-right">
                  <p className="text-[10px] text-[#39FF14]/30 uppercase">Operator</p>
                  <p className="text-xs font-bold truncate max-w-[120px]">{user.displayName || user.email}</p>
                  {isAdmin && <span className="text-[7px] text-red-500 font-black uppercase">Level_10_Admin</span>}
               </div>
               <button 
                 onClick={handleLogout}
                 className="p-2 bg-red-500/10 border border-red-500/30 text-red-500 hover:bg-red-500/20 transition-all"
               >
                 <Lock size={14} />
               </button>
            </div>
          ) : (
            <button 
               onClick={login}
               className="flex items-center gap-2 px-4 py-2 bg-[#39FF14]/10 border border-[#39FF14]/30 text-[#39FF14] text-[10px] font-black uppercase hover:bg-[#39FF14]/20 transition-all border-r pr-6"
            >
               <User size={14} /> AUTH_INIT
            </button>
          )}
          <div className="text-right border-r border-[#39FF14]/10 pr-6">
            <p className="text-[10px] text-[#39FF14]/30 uppercase">System_Clock</p>
            <p className="text-xs font-bold">{new Date().toLocaleTimeString()}</p>
          </div>
          <div className="text-right">
            <p className="text-[10px] text-[#39FF14]/30 uppercase">Analysis_Pulse</p>
            <p className="text-xs text-[#39FF14] flex items-center gap-1 animate-pulse"><Activity size={12} /> Synchronized</p>
          </div>
        </div>
      </header>

      <main className="max-w-[1600px] mx-auto grid grid-cols-1 lg:grid-cols-12 gap-4 pb-24">
        
        {/* TOP ROW: LOGO & STATUS (MOBILE ONLY) */}
        <div className="lg:hidden col-span-full">
           <section className="glass-panel border-[#39FF14]/20 p-4 flex justify-between items-center bg-black/60">
              <div className="flex items-center gap-2">
                 <Shield className="text-[#39FF14]" size={20} />
                 <span className="font-black italic text-sm">Cyber Shield AI</span>
              </div>
              <div className="flex items-center gap-2 text-[10px]">
                 <div className="w-2 h-2 bg-[#39FF14] animate-ping rounded-full" />
                 <span>OS_UPTIME: 14h 22m</span>
              </div>
           </section>
        </div>

        {/* LEFT COLUMN: CONTROL & INPUT (Col 3) */}
        <div className="lg:col-span-3 space-y-4">
          <div className="flex gap-2">
            <button 
              onClick={() => setActiveTab('scan')}
              className={cn(
                "flex-1 py-2 text-[10px] font-black uppercase tracking-widest border transition-all",
                activeTab === 'scan' ? "bg-[#39FF14]/10 border-[#39FF14] text-[#39FF14]" : "border-[#39FF14]/10 text-[#39FF14]/30 hover:border-[#39FF14]/30"
              )}
            >
              SCANNER
            </button>
            <button 
              onClick={() => setActiveTab('history')}
              className={cn(
                "flex-1 py-2 text-[10px] font-black uppercase tracking-widest border transition-all",
                activeTab === 'history' ? "bg-blue-500/10 border-blue-500 text-blue-400" : "border-blue-500/10 text-blue-500/30 hover:border-blue-500/30"
              )}
            >
              HISTORY
            </button>
          </div>

          {activeTab === 'scan' ? (
            <>
              <section className="glass-panel border-[#39FF14]/30 bg-black/80 neon-border p-4">
            <div className="flex items-center justify-between mb-4">
               <h2 className="text-[10px] text-[#39FF14] font-bold uppercase tracking-[0.3em] flex items-center gap-2">
                  <Terminal size={12} /> SCANNER_INIT
               </h2>
               <div className="flex gap-1">
                  <div className="w-1.5 h-1.5 border border-[#39FF14]/30" />
                  <div className="w-1.5 h-1.5 bg-[#39FF14]" />
               </div>
            </div>
            
            <form onSubmit={handleAnalyze} className="space-y-4">
              <div className="relative group">
                <div className="absolute -inset-0.5 bg-[#39FF14]/20 blur opacity-0 group-hover:opacity-100 transition duration-500" />
                <input 
                  type="text"
                  placeholder="URL / IP / EMAIL / PHONE / MESSAGE"
                  className={cn(
                    "relative w-full bg-black border rounded-none px-4 py-3 text-xs md:text-sm focus:outline-none transition-all placeholder:text-[#39FF14]/20 font-mono",
                    urlError ? "border-red-500 shadow-[0_0_15px_rgba(239,68,68,0.3)]" : "border-[#39FF14]/30 focus:border-[#39FF14] focus:shadow-[0_0_15px_rgba(57,255,20,0.2)]"
                  )}
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                />
                <div className="absolute right-3 top-1/2 -translate-y-1/2 text-[#39FF14]/30 group-hover:text-[#39FF14] transition-colors">
                  <Search size={16} />
                </div>
              </div>
              
              <AnimatePresence>
                {urlError && (
                  <motion.p 
                    initial={{ opacity: 0, y: -5 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -5 }}
                    className="text-[10px] text-red-500 font-bold flex items-center gap-1"
                  >
                    <AlertTriangle size={10} /> {urlError}
                  </motion.p>
                )}
              </AnimatePresence>

              <button 
                disabled={isAnalyzing || !url || !!urlError}
                className="w-full bg-[#39FF14] text-black font-black py-4 rounded-none flex items-center justify-center gap-2 hover:bg-[#39FF14]/90 active:scale-[0.98] transition-all disabled:opacity-30 disabled:cursor-not-allowed group shadow-[0_0_20px_rgba(57,255,20,0.1)]"
              >
                {isAnalyzing ? (
                  <RefreshCcw size={18} className="animate-spin" />
                ) : (
                  <>
                    <Zap size={18} className="group-hover:scale-125 transition-transform" />
                    EXECUTE_ANALYSIS
                  </>
                )}
              </button>

              <div className="grid grid-cols-2 gap-2 mt-4">
                 {scannerModes.map((mode) => (
                    <button
                      key={mode.id}
                      type="button"
                      onClick={() => {
                        setUrl(mode.example);
                        handleAnalyze(undefined, mode.example);
                      }}
                      className="flex items-center gap-2 px-2 py-2 bg-black border border-[#39FF14]/10 hover:border-[#39FF14]/40 hover:bg-[#39FF14]/5 transition-all group"
                    >
                      <mode.icon size={12} className="text-[#39FF14]/40 group-hover:text-[#39FF14]" />
                      <span className="text-[9px] font-black tracking-tighter text-[#39FF14]/60 group-hover:text-[#39FF14]">{mode.label}</span>
                    </button>
                 ))}
              </div>
            </form>
          </section>

          <section className="glass-panel border-blue-500/30 bg-black/80 p-4 relative overflow-hidden group">
            <div className="absolute top-0 right-0 w-16 h-16 bg-blue-500/5 -rotate-45 translate-x-8 -translate-y-8" />
            <div className="flex items-center justify-between mb-4">
               <h2 className="text-[10px] text-blue-400 font-bold uppercase tracking-[0.3em] flex items-center gap-2">
                  <Activity size={12} /> IP_ADDRESS_PROBE
               </h2>
               <div className="flex gap-1">
                  <div className="w-1.5 h-1.5 bg-blue-500/10 border border-blue-500/20" />
                  <div className="w-1.5 h-1.5 bg-blue-500 animate-pulse shadow-[0_0_10px_rgba(59,130,246,0.5)]" />
               </div>
            </div>
            
            <div className="space-y-4">
              <input 
                type="text"
                placeholder="185.156.174.20"
                className={cn(
                  "w-full bg-black border rounded-none px-4 py-3 text-xs md:text-sm focus:outline-none transition-all placeholder:text-blue-500/20 font-mono",
                  ipError ? "border-red-500 shadow-[0_0_15px_rgba(239,68,68,0.3)]" : "border-blue-500/30 focus:border-blue-500 focus:shadow-[0_0_15px_rgba(59,130,246,0.2)]"
                )}
                value={ipAddress}
                onChange={(e) => {
                  setIpAddress(e.target.value);
                  validateIp(e.target.value);
                }}
              />
              
              <button 
                onClick={() => handleAnalyze(undefined, ipAddress)}
                disabled={isAnalyzing || !ipAddress || !!ipError}
                className="w-full bg-blue-600 text-white font-black py-3 rounded-none flex items-center justify-center gap-2 hover:bg-blue-500 active:scale-[0.98] transition-all disabled:opacity-20 disabled:cursor-not-allowed group uppercase tracking-widest text-[10px]"
              >
                {isAnalyzing ? (
                  <RefreshCcw size={14} className="animate-spin" />
                ) : (
                  <>
                    <Activity size={14} className="group-hover:animate-pulse" />
                    INIT_REPU_SCAN
                  </>
                )}
              </button>
            </div>
          </section>

          <section className="glass-panel border-purple-500/30 bg-black/80 p-4 relative overflow-hidden group">
            <div className="absolute top-0 right-0 w-16 h-16 bg-purple-500/5 -rotate-45 translate-x-8 -translate-y-8" />
            <div className="flex items-center justify-between mb-4">
               <h2 className="text-[10px] text-purple-400 font-bold uppercase tracking-[0.3em] flex items-center gap-2">
                  <Zap size={12} /> EMAIL_ENTITY_AUDIT
               </h2>
               <div className="flex gap-1">
                  <div className="w-1.5 h-1.5 bg-purple-500/10 border border-purple-500/20" />
                  <div className="w-1.5 h-1.5 bg-purple-500 animate-pulse shadow-[0_0_10px_rgba(168,85,247,0.5)]" />
               </div>
            </div>
            
            <div className="space-y-4">
              <input 
                type="text"
                placeholder="operator@target-infra.net"
                className={cn(
                  "w-full bg-black border rounded-none px-4 py-3 text-xs md:text-sm focus:outline-none transition-all placeholder:text-purple-500/20 font-mono",
                  emailError ? "border-red-500 shadow-[0_0_15px_rgba(239,68,68,0.3)]" : "border-purple-500/30 focus:border-purple-500 focus:shadow-[0_0_15px_rgba(168,85,247,0.2)]"
                )}
                value={emailAddress}
                onChange={(e) => {
                  setEmailAddress(e.target.value);
                  validateEmail(e.target.value);
                }}
              />
              
              <button 
                onClick={() => handleAnalyze(undefined, emailAddress)}
                disabled={isAnalyzing || !emailAddress || !!emailError}
                className="w-full bg-purple-600 text-white font-black py-3 rounded-none flex items-center justify-center gap-2 hover:bg-purple-500 active:scale-[0.98] transition-all disabled:opacity-20 disabled:cursor-not-allowed group uppercase tracking-widest text-[10px]"
              >
                {isAnalyzing ? (
                  <RefreshCcw size={14} className="animate-spin" />
                ) : (
                  <>
                    <Zap size={14} className="group-hover:animate-pulse" />
                    INIT_MX_PROBE
                  </>
                )}
              </button>
            </div>
          </section>

          <section className="glass-panel border-indigo-500/30 bg-black/80 p-4 relative overflow-hidden group">
            <div className="absolute top-0 right-0 w-16 h-16 bg-indigo-500/5 -rotate-45 translate-x-8 -translate-y-8" />
            <div className="flex items-center justify-between mb-4">
               <h2 className="text-[10px] text-indigo-400 font-bold uppercase tracking-[0.3em] flex items-center gap-2">
                  <Globe size={12} /> DOMAIN_NAMESPACE_SCAN
               </h2>
               <div className="flex gap-1">
                  <div className="w-1.5 h-1.5 bg-indigo-500/10 border border-indigo-500/20" />
                  <div className="w-1.5 h-1.5 bg-indigo-500 animate-pulse shadow-[0_0_10px_rgba(99,102,241,0.5)]" />
               </div>
            </div>
            
            <div className="space-y-4">
              <input 
                type="text"
                placeholder="secure-login-gateway.com"
                className={cn(
                  "w-full bg-black border rounded-none px-4 py-3 text-xs md:text-sm focus:outline-none transition-all placeholder:text-indigo-500/20 font-mono",
                  domainError ? "border-red-500 shadow-[0_0_15px_rgba(239,68,68,0.3)]" : "border-indigo-500/30 focus:border-indigo-500 focus:shadow-[0_0_15px_rgba(99,102,241,0.2)]"
                )}
                value={domainName}
                onChange={(e) => {
                  setDomainName(e.target.value);
                  validateDomain(e.target.value);
                }}
              />
              
              <button 
                onClick={() => handleAnalyze(undefined, domainName)}
                disabled={isAnalyzing || !domainName || !!domainError}
                className="w-full bg-indigo-600 text-white font-black py-3 rounded-none flex items-center justify-center gap-2 hover:bg-indigo-500 active:scale-[0.98] transition-all disabled:opacity-20 disabled:cursor-not-allowed group uppercase tracking-widest text-[10px]"
              >
                {isAnalyzing ? (
                  <RefreshCcw size={14} className="animate-spin" />
                ) : (
                  <>
                    <Globe size={14} className="group-hover:animate-pulse" />
                    INIT_DNS_AUDIT
                  </>
                )}
              </button>
            </div>
          </section>
            </>
          ) : (
            <section className="glass-panel border-blue-500/30 bg-black/80 p-5 min-h-[400px]">
              <ScanHistory onSelect={(report) => {
                setResult(report);
                setActiveTab('scan');
                addLog(`RESTORED_THREAT_REPORT: ${report.target}`);
              }} />
            </section>
          )}

          <QRScannerModule onScan={(text) => {
            setUrl(text);
            handleAnalyze(undefined, text);
          }} />

          <GlobalMap />
          <ExtensionModule />
          <section className="glass-panel border-amber-500/30 bg-black/80 p-4 relative overflow-hidden group">
            <div className="absolute top-0 right-0 w-16 h-16 bg-amber-500/5 -rotate-45 translate-x-8 -translate-y-8" />
            <div className="flex items-center justify-between mb-4">
               <h2 className="text-[10px] text-amber-500 font-bold uppercase tracking-[0.3em] flex items-center gap-2">
                  <MessageSquare size={12} /> SMS_CONTENT_AUDITOR
               </h2>
               <div className="flex gap-1">
                  <div className="w-1.5 h-1.5 bg-amber-500/10 border border-amber-500/20" />
                  <div className="w-1.5 h-1.5 bg-amber-500 animate-pulse" />
               </div>
            </div>
            
            <div className="space-y-4">
              <div className="relative group">
                <textarea 
                  placeholder="Paste SMS/Message body here for semantic threat analysis..."
                  rows={4}
                  className={cn(
                    "w-full bg-black border rounded-none px-4 py-3 text-xs md:text-sm focus:outline-none transition-all placeholder:text-amber-500/20 font-mono resize-none",
                    messageError ? "border-red-500 shadow-[0_0_15px_rgba(239,68,68,0.3)]" : "border-amber-500/30 focus:border-amber-500 focus:shadow-[0_0_15px_rgba(245,158,11,0.2)]"
                  )}
                  value={messageContent}
                  onChange={(e) => {
                    setMessageContent(e.target.value);
                    validateMessage(e.target.value);
                  }}
                />
              </div>
              
              <AnimatePresence>
                {messageError && (
                  <motion.p 
                    initial={{ opacity: 0, scale: 0.9 }}
                    animate={{ opacity: 1, scale: 1 }}
                    className="text-[9px] text-red-500 font-black flex items-center gap-1 uppercase italic"
                  >
                    <AlertTriangle size={10} /> {messageError}
                  </motion.p>
                )}
              </AnimatePresence>

              <button 
                onClick={() => handleAnalyze(undefined, messageContent)}
                disabled={isAnalyzing || !messageContent || !!messageError}
                className="w-full bg-amber-600 text-white font-black py-3 rounded-none flex items-center justify-center gap-2 hover:bg-amber-500 active:scale-[0.98] transition-all disabled:opacity-20 disabled:cursor-not-allowed group uppercase tracking-widest text-[10px]"
              >
                {isAnalyzing ? (
                  <RefreshCcw size={14} className="animate-spin" />
                ) : (
                  <>
                    <Search size={14} className="group-hover:animate-pulse" />
                    AUDIT_MESSAGE_BODY
                  </>
                )}
              </button>
              
              <div className="flex justify-between items-center text-[7px] opacity-30 pt-2 border-t border-amber-500/10">
                 <span>ENGINE: SEMANTIC_HEURISTICS</span>
                 <span>VERSION: 4.2.0_STABLE</span>
              </div>
            </div>
          </section>

          <section className="glass-panel border-emerald-500/30 bg-black/80 p-4 relative overflow-hidden group">
            <div className="absolute top-0 right-0 w-16 h-16 bg-emerald-500/5 -rotate-45 translate-x-8 -translate-y-8" />
            <div className="flex items-center justify-between mb-4">
               <h2 className="text-[10px] text-emerald-400 font-bold uppercase tracking-[0.3em] flex items-center gap-2">
                  <Activity size={12} /> TELEPHONY_SCANNER
               </h2>
               <div className="flex gap-1">
                  <div className="w-1.5 h-1.5 bg-emerald-500/10 border border-emerald-500/20" />
                  <div className="w-1.5 h-1.5 bg-emerald-500 animate-pulse" />
               </div>
            </div>
            
            <div className="space-y-4">
              <input 
                type="text"
                placeholder="+1-XXX-XXX-XXXX"
                className={cn(
                  "w-full bg-black border rounded-none px-4 py-3 text-xs md:text-sm focus:outline-none transition-all placeholder:text-emerald-500/20 font-mono",
                  phoneError ? "border-red-500 shadow-[0_0_15px_rgba(239,68,68,0.3)]" : "border-emerald-500/30 focus:border-emerald-500 focus:shadow-[0_0_15px_rgba(16,185,129,0.2)]"
                )}
                value={phoneAddress}
                onChange={(e) => {
                  setPhoneAddress(e.target.value);
                  validatePhone(e.target.value);
                }}
              />
              
              <button 
                onClick={() => handleAnalyze(undefined, phoneAddress)}
                disabled={isAnalyzing || !phoneAddress || !!phoneError}
                className="w-full bg-emerald-600 text-white font-black py-3 rounded-none flex items-center justify-center gap-2 hover:bg-emerald-500 active:scale-[0.98] transition-all disabled:opacity-20 disabled:cursor-not-allowed group uppercase tracking-widest text-[10px]"
              >
                {isAnalyzing ? (
                  <RefreshCcw size={14} className="animate-spin" />
                ) : (
                  <>
                    <Activity size={14} className="group-hover:animate-pulse" />
                    INIT_PHONE_PROBE
                  </>
                )}
              </button>
            </div>
          </section>

          <KeywordMonitor />
          {/* Remotely Integrated Consoles removed for cleaner main dashboard integration */}
          <section className="glass-panel border-[#39FF14]/10 bg-black/60 p-4 h-[300px] flex flex-col">
            <div className="flex items-center justify-between mb-3">
               <h2 className="text-[10px] text-[#39FF14]/40 uppercase tracking-[0.2em] flex items-center gap-2">
                  <Activity size={12} /> CONSOLE_LOG
               </h2>
               <span className="text-[8px] opacity-30">TTY: /dev/pts/0</span>
            </div>
            <div 
              ref={scrollRef}
              className="flex-1 overflow-y-auto space-y-1 text-[11px] font-mono leading-tight custom-scrollbar"
            >
              {logs.length === 0 && <p className="text-[#39FF14]/20 italic">IDLE_STATE: AWAITING_CMD...</p>}
              {logs.map((log, i) => (
                <div key={i} className="flex gap-2">
                  <span className="text-[#39FF14]/20 flex-shrink-0">{`·`}</span>
                  <p className={cn(
                    log.includes('COMPLETE') ? 'text-[#39FF14]' :
                    log.includes('ERROR') ? 'text-red-500' :
                    log.includes('INITIATING') ? 'text-[#39FF14] brightness-125' : 'text-[#39FF14]/60'
                  )}>{log}</p>
                </div>
              ))}
            </div>
            <div className="mt-3 pt-2 border-t border-[#39FF14]/10 flex justify-between items-center text-[9px] opacity-40">
               <div className="flex items-center gap-2">
                  <div className="w-1.5 h-1.5 bg-[#39FF14] animate-pulse" />
                  <span>PROCESS_READY</span>
               </div>
               <span>{logs.length} LINES</span>
            </div>
          </section>

          <MatrixEffect />

          <section className="glass-panel border-[#39FF14]/20 bg-[#39FF14]/5 p-4 neon-border">
            <h3 className="text-[10px] font-black uppercase tracking-widest text-[#39FF14] mb-3 flex items-center gap-2">
               <Globe size={14} /> SIDECAR.EXT
            </h3>
            <p className="text-[11px] text-[#39FF14]/60 leading-relaxed mb-4">
              Real-time heuristic injection for active browsing monitoring.
            </p>
            <div className="flex gap-2">
               <div className="px-2 py-1 bg-black border border-[#39FF14]/30 text-[8px] font-bold">V1.2_STABLE</div>
               <div className="px-2 py-1 bg-black border border-[#39FF14]/30 text-[8px] font-bold">CHROME_SYNC</div>
            </div>
          </section>
        </div>

        {/* MIDDLE COLUMN: RESULTS (Col 6) */}
        <div className="lg:col-span-6">
          <AnimatePresence mode="wait">
            {!result && !isAnalyzing && !analysisError && (
              <motion.div 
                key="idle"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="h-full min-h-[500px] glass-panel border-dashed border-[#39FF14]/10 bg-[#39FF14]/[0.01] flex flex-col items-center justify-center relative group"
              >
                {/* Decorative scanning elements */}
                <div className="absolute inset-0 overflow-hidden pointer-events-none opacity-10">
                   <div className="absolute top-0 w-full h-px bg-[#39FF14] animate-[scan_3s_infinite_ease-in-out]" />
                   <div className="grid grid-cols-10 h-full">
                      {Array.from({ length: 10 }).map((_, i) => (
                        <div key={i} className="border-r border-[#39FF14]/20 h-full" />
                      ))}
                   </div>
                </div>

                <div className="p-8 rounded-none border border-[#39FF14]/20 bg-black/60 shadow-[0_0_30px_rgba(57,255,20,0.1)] relative z-10 transition-transform group-hover:scale-110 duration-500">
                  <Shield size={48} className="text-[#39FF14] opacity-50" strokeWidth={1} />
                </div>
                <h3 className="text-xl font-black tracking-[0.2em] mt-6 mb-2 text-[#39FF14]/80">AWAITING_PAYLOAD</h3>
                <p className="text-[#39FF14]/40 text-[10px] uppercase font-mono tracking-[0.3em] max-w-xs text-center border-t border-[#39FF14]/10 pt-4 mt-2">
                  System standing by. Enter a target URI to begin deep heuristic decomposition.
                </p>
              </motion.div>
            )}

            {analysisError && (
              <motion.div 
                key="error"
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                className="h-full min-h-[500px] glass-panel border-red-500/20 bg-red-500/5 flex flex-col items-center justify-center text-center p-8"
              >
                <div className="p-4 bg-red-500/20 border border-red-500 mb-6">
                   <AlertTriangle className="text-red-500" size={40} />
                </div>
                <h2 className="text-2xl font-black italic tracking-widest text-red-500 mb-4 uppercase">System_Fault_Detected</h2>
                <div className="max-w-md bg-black/60 border border-white/5 p-4 rounded mb-6">
                   <p className="text-[12px] font-mono text-zinc-400 leading-relaxed">
                     {analysisError}
                   </p>
                </div>
                <button 
                  onClick={() => setAnalysisError(null)}
                  className="px-6 py-2 bg-red-500/20 border border-red-500 text-red-500 text-[10px] font-black uppercase tracking-widest hover:bg-red-500 hover:text-white transition-all"
                >
                  DISMISS_FAULT_REPORT
                </button>
              </motion.div>
            )}

            {isAnalyzing && (
              <motion.div 
                key="loading"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="h-full min-h-[500px] glass-panel border-[#39FF14]/10 flex flex-col items-center justify-center relative overflow-hidden"
              >
                <div className="absolute inset-0 bg-[#39FF14]/2 blur-[100px]" />
                <div className="relative z-10 text-center">
                  <div className="inline-block p-6 border-2 border-[#39FF14] rounded-none mb-6 animate-pulse shadow-[0_0_30px_rgba(57,255,20,0.3)]">
                    <RefreshCcw size={48} className="animate-spin text-[#39FF14]" />
                  </div>
                  <h2 className="text-2xl font-black italic tracking-widest text-[#39FF14]">ANALYZING_FLIGHT_VECTORS</h2>
                  <div className="flex gap-2 justify-center mt-6">
                    {Array.from({ length: 5 }).map((_, i) => (
                      <motion.div 
                        key={i} 
                        className="w-2 h-2 bg-[#39FF14]"
                        animate={{ opacity: [0.2, 1, 0.2] }}
                        transition={{ duration: 0.8, repeat: Infinity, delay: i * 0.1 }}
                      />
                    ))}
                  </div>
                </div>
              </motion.div>
            )}

            {result && (
              <motion.div 
                key="result"
                ref={dashboardRef}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="space-y-4"
              >
                <div className={cn(
                  "p-8 glass-panel border neon-border relative overflow-hidden",
                  getStatusColor(result.classification).split(' ').slice(1).join(' ')
                )}>
                  <div className="absolute top-0 right-0 w-80 h-80 opacity-[0.03] pointer-events-none translate-x-1/4 -translate-y-1/4">
                    <Shield size={320} className="text-[#39FF14]" />
                  </div>
                  
                  <div className="flex flex-col md:flex-row items-center gap-8 relative z-10">
                    <ThreatGauge score={result.threatScore} />
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-3">
                        <span className={cn("status-badge shadow-[0_0_15px_currentColor]", getStatusColor(result.classification).split(' ')[0])}>
                           {result.classification}
                        </span>
                        <div className="h-px flex-1 bg-[#39FF14]/10" />
                      </div>
                      <h2 className="text-3xl md:text-5xl font-black italic tracking-tighter mb-1">
                        INDEX: <span className={getGaugeColor(result.threatScore)}>{result.threatScore}.00</span>
                      </h2>
                      <div className="flex items-center gap-4 text-[10px] font-mono text-[#39FF14]/70">
                         <span className="flex items-center gap-1"><Lock size={10} /> TARGET_TYPE: {result.type?.toUpperCase()}</span>
                         <span className="flex items-center gap-1"><Cpu size={10} /> CORE_SYNC: OK</span>
                      </div>
                    </div>
                  </div>

                  <div className="mt-8 pt-8 border-t border-[#39FF14]/10 grid grid-cols-1 md:grid-cols-2 gap-6 bg-black/40 p-6 -mx-8 -mb-8">
                     <div className="relative pl-6 border-l-2 border-[#39FF14]/20">
                        <div className="absolute -top-1 -left-1.5 w-3 h-3 bg-black border border-[#39FF14]/30 rotate-45" />
                        <p className="text-[10px] font-bold text-[#39FF14]/50 uppercase tracking-[0.3em] mb-2">Security_Directive</p>
                        <p className="text-[13px] leading-relaxed italic text-[#39FF14]">{result.recommendation}</p>
                     </div>
                     <div className="bg-black/80 p-4 border border-[#39FF14]/10 flex flex-col justify-between relative group">
                        <div className="absolute inset-0 bg-[#39FF14]/5 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none" />
                        <button 
                         onClick={captureReport}
                         className="absolute top-2 right-2 p-1.5 border border-[#39FF14]/20 hover:border-[#39FF14] hover:bg-[#39FF14]/10 text-[#39FF14] transition-all z-20"
                         title="CAPTURE_INTEL_FOR_REPORT"
                       >
                          <Camera size={14} />
                       </button>
                        <div className="flex justify-between items-center text-[10px] mb-2 opacity-50">
                           <span>NEURAL_SUMMARY</span>
                           <Zap size={10} />
                        </div>
                        <p className="text-[11px] leading-relaxed line-clamp-3 text-[#39FF14]/80 italic">
                          "{result.explanation}"
                        </p>
                     </div>
                  </div>
                </div>

                <ReputationModule result={result} />
                <VulnerabilityModule result={result} />
                <PhoneModule result={result} />
                <MessageModule result={result} />
                <VisualEvidenceModule result={result} />
                
                {result.type !== 'keyword' && result.type !== 'phone' && result.type !== 'message' && (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {/* SSL MODULE */}
                  <div className="glass-panel border-[#39FF14]/20 p-5 space-y-4">
                    <div className="flex justify-between items-start">
                       <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-[#39FF14] flex items-center gap-2">
                         <Lock size={12} className="text-blue-400" /> SSL_HANDSHAKE
                       </h3>
                       <div className="w-2 h-2 bg-blue-500 rounded-full animate-pulse" />
                    </div>
                    <div className="p-3 bg-black border border-[#39FF14]/10 space-y-2 text-[10px]">
                       <div className="flex justify-between">
                          <span className="opacity-40 uppercase">Authorization</span>
                          <span className={cn("font-bold", result.raw?.ssl?.authorized ? "text-[#39FF14]" : "text-red-500")}>
                             {result.raw?.ssl?.authorized ? "TRUSTED" : (result.raw?.ssl?.error ? "FAILED" : "UNSAFE")}
                          </span>
                       </div>
                       {result.raw?.ssl?.issuer && (
                         <div className="flex justify-between items-start pt-1 border-t border-[#39FF14]/5">
                            <span className="opacity-40 uppercase">Issuer</span>
                            <span className="font-bold text-right truncate max-w-[140px]" title={result.raw.ssl.issuer.O || result.raw.ssl.issuer.CN}>
                               {result.raw.ssl.issuer.O || result.raw.ssl.issuer.CN || 'Unknown'}
                            </span>
                         </div>
                       )}
                       <div className="flex justify-between items-center pt-1 border-t border-[#39FF14]/5">
                          <span className="opacity-40 uppercase">Valid From</span>
                          <span className="font-bold">{result.raw?.ssl?.valid_from ? new Date(result.raw.ssl.valid_from).toLocaleDateString() : 'N/A'}</span>
                       </div>
                       <div className="flex justify-between items-center relative group/expiry">
                          <span className="opacity-40 uppercase">Valid To</span>
                          <div className="flex items-center gap-1.5">
                            <span className={cn(
                              "font-bold", 
                              new Date(result.raw?.ssl?.valid_to) < new Date() 
                                ? "text-red-500" 
                                : (result.raw?.ssl?.valid_to && new Date(result.raw.ssl.valid_to).getTime() - new Date().getTime() < 30 * 24 * 60 * 60 * 1000)
                                  ? "text-orange-500"
                                  : ""
                            )}>
                               {result.raw?.ssl?.valid_to ? new Date(result.raw.ssl.valid_to).toLocaleDateString() : 'N/A'}
                            </span>
                            {(result.raw?.ssl?.valid_to && 
                              new Date(result.raw.ssl.valid_to).getTime() - new Date().getTime() < 30 * 24 * 60 * 60 * 1000 && 
                              new Date(result.raw.ssl.valid_to).getTime() > new Date().getTime()) && (
                              <div className="flex items-center gap-1 bg-orange-500/10 border border-orange-500/20 px-1 rounded-sm animate-pulse">
                                <AlertTriangle size={8} className="text-orange-400" />
                                <span className="absolute hidden group-hover/expiry:block right-0 -top-6 bg-black border border-orange-500/50 text-orange-400 text-[7px] px-2 py-1 whitespace-nowrap z-50 uppercase font-black">
                                  Expiring Soon (&lt;30D)
                                </span>
                              </div>
                            )}
                          </div>
                       </div>
                       {result.raw?.ssl?.fingerprint && (
                         <div className="pt-1 border-t border-[#39FF14]/5">
                            <p className="opacity-40 uppercase mb-1">Fingerprint (SHA1)</p>
                            <p className="font-mono text-[8px] break-all opacity-80 leading-tight">
                               {result.raw.ssl.fingerprint}
                            </p>
                         </div>
                       )}
                       <div className="flex justify-between border-t border-[#39FF14]/5 pt-2">
                          <span className="opacity-40 uppercase">CT Logs</span>
                          <span className="font-bold">{result.raw?.ct?.length || 0} RECORDS</span>
                       </div>
                    </div>
                    <p className="text-[9px] leading-relaxed text-[#39FF14]/60 italic font-sans px-1">
                       {result.technicalSummary.ssl}
                    </p>
                  </div>

                  {/* DNS MODULE */}
                  <div className="glass-panel border-[#39FF14]/20 p-5 space-y-4">
                    <div className="flex justify-between items-start">
                       <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-[#39FF14] flex items-center gap-2">
                         <Globe size={12} className="text-emerald-400" /> DNS_RESOLVER
                       </h3>
                       <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse shadow-[0_0_10px_rgba(16,185,129,0.5)]" />
                    </div>
                    <div className="p-3 bg-black border border-[#39FF14]/10 space-y-2 text-[10px]">
                       <div className="flex justify-between">
                          <span className="opacity-40">PRIMARY_IP</span>
                          <span className="font-bold text-[#39FF14]">{result.raw?.dns?.ips?.[0] || 'N.A'}</span>
                       </div>
                       <div className="flex justify-between">
                          <span className="opacity-40">DNSBL_STATUS</span>
                          <span className={cn("font-bold", result.raw?.dns?.reputation?.length > 0 ? "text-red-500" : "text-[#39FF14]")}>
                             {result.raw?.dns?.reputation?.length > 0 ? "LISTED" : "CLEAN"}
                          </span>
                       </div>
                       {result.type === 'email' && result.raw?.dns?.records?.mx?.length > 0 && (
                         <div className="pt-2 border-t border-[#39FF14]/5 space-y-1">
                            <p className="opacity-40 uppercase mb-1">MX_RECORDS</p>
                            {result.raw.dns.records.mx.slice(0, 2).map((mx: any, i: number) => (
                              <div key={i} className="flex justify-between text-[8px] italic">
                                <span className="truncate max-w-[120px]">{mx.exchange}</span>
                                <span className="font-mono text-emerald-500">PRI: {mx.priority}</span>
                              </div>
                            ))}
                         </div>
                       )}
                    </div>
                    <p className="text-[9px] leading-relaxed text-[#39FF14]/60 italic font-sans px-1">
                       {result.technicalSummary.dns}
                    </p>
                  </div>

                  {/* HEURISTICS MODULE */}
                  <div className="glass-panel border-[#39FF14]/20 p-5 space-y-4">
                    <div className="flex justify-between items-start">
                       <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-[#39FF14] flex items-center gap-2">
                         <Cpu size={12} className="text-orange-400" /> PATTERN_ENG
                       </h3>
                       <div className="w-2 h-2 bg-orange-500 rounded-full animate-pulse shadow-[0_0_10px_rgba(249,115,22,0.5)]" />
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-[10px]">
                       <div className="p-2 bg-black border border-[#39FF14]/10">
                          <p className="opacity-30 mb-1">ENTROPY</p>
                          <p className="font-bold text-[#39FF14]">{result.raw?.heuristics?.entropy?.toFixed(2) || '0.0'}</p>
                       </div>
                       <div className="p-2 bg-black border border-[#39FF14]/10">
                          <p className="opacity-30 mb-1">PUNYCODE</p>
                          <p className={cn("font-bold", result.raw?.heuristics?.isPunycode ? "text-red-500" : "text-[#39FF14]")}>
                             {result.raw?.heuristics?.isPunycode ? "YES" : "NO"}
                          </p>
                       </div>
                    </div>
                    <div className="flex gap-2">
                       {result.riskIndicators.slice(0, 2).map((risk, i) => (
                          <span key={i} className="text-[8px] bg-[#39FF14]/10 border border-[#39FF14]/20 px-2 py-0.5 uppercase tracking-widest text-[#39FF14]">
                             {risk}
                          </span>
                       ))}
                    </div>
                  </div>
                </div>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* RIGHT COLUMN: TECHNICAL DETAILS / INTEL (Col 3) */}
        <div className="lg:col-span-3 space-y-4">
           {/* INTEL FEED INTEGRATED */}
           <section className="glass-panel border-[#39FF14]/20 bg-black/40 p-5 space-y-4">
              <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-[#39FF14] flex items-center gap-2">
                <Zap size={12} className="text-red-500 shadow-[0_0_10px_rgba(239,68,68,0.5)]" /> INTEL_FEEDS
              </h3>
              <div className="space-y-4">
                 <div className="space-y-1">
                    <p className="text-[9px] opacity-30 uppercase font-black">LYZR_MALWARE_DB</p>
                    <div className="h-1 bg-[#39FF14]/10 relative">
                       <motion.div 
                        className="absolute h-full bg-[#39FF14]"
                        initial={{ width: 0 }}
                        animate={{ width: "82%" }}
                       />
                    </div>
                    <p className="text-[9px] text-[#39FF14] font-bold">82% CONFIDENCE MATCH</p>
                 </div>
                 <div className="p-3 bg-black/60 border-l-2 border-red-500 text-[10px] italic text-[#39FF14]/70">
                    "Pattern signatures matched global polymorphic phishing campaign identifiers recorded T-minus 48h."
                 </div>
              </div>
           </section>

           {/* DOMAIN BIO */}
           {result && result.type !== 'keyword' && result.type !== 'phone' && result.type !== 'message' && (
             <motion.section 
               initial={{ opacity: 0, x: 20 }}
               animate={{ opacity: 1, x: 0 }}
               className="glass-panel border-[#39FF14]/20 p-5 space-y-4 neon-border"
             >
                <div className="flex items-center gap-3">
                   <CalendarDays className="text-purple-500" size={16} />
                   <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-[#39FF14]">DOMAIN_RECORDS</h3>
                </div>
                <div className="space-y-3">
                   <div>
                      <p className="text-[32px] font-black tracking-tighter text-[#39FF14] leading-none mb-1">
                         {getDomainAge(result.raw?.whois?.creationDate || result.raw?.whois?.createdDate) || 'INF'}
                      </p>
                      <p className="text-[8px] opacity-30 uppercase font-black tracking-widest">Calculated_Epoch_Time</p>
                   </div>
                   <div className="p-3 bg-black/80 border border-[#39FF14]/10 space-y-2 text-[9px]">
                      <div className="flex justify-between">
                         <span className="opacity-40">CREATED</span>
                         <span className="text-[#39FF14] truncate max-w-[120px]">{result.raw?.whois?.creationDate || result.raw?.whois?.createdDate || 'N/A'}</span>
                      </div>
                      <div className="flex justify-between">
                         <span className="opacity-40">EXPIRES</span>
                         <span className="text-[#39FF14] truncate max-w-[120px]">{result.raw?.whois?.expiryDate || result.raw?.whois?.expirationDate || 'N/A'}</span>
                      </div>
                      <div className="flex justify-between">
                         <span className="opacity-40">REGISTRAR</span>
                         <span className="text-[#39FF14] truncate max-w-[120px]">{result.raw?.whois?.registrar || 'N/A'}</span>
                      </div>
                      {result.raw?.whois?.registrarAbuseContactEmail && (
                        <div className="flex justify-between">
                           <span className="opacity-40">ABUSE_EMAIL</span>
                           <span className="text-[#39FF14] truncate max-w-[120px]">{result.raw.whois.registrarAbuseContactEmail}</span>
                        </div>
                      )}
                   </div>
                   <p className="text-[9px] leading-relaxed text-[#39FF14]/50 italic">
                      {result.technicalSummary.whois}
                   </p>
                </div>
             </motion.section>
           )}

           {/* SYSTEM STATS */}
           <section className="glass-panel border-[#39FF14]/10 p-5 space-y-4">
              <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-[#39FF14] flex items-center gap-2">
                <Cpu size={12} /> HARDWARE_OS
              </h3>
              <div className="space-y-3">
                 <div className="flex justify-between items-end">
                    <p className="text-[9px] opacity-30 uppercase">CPU_LOAD</p>
                    <div className="flex gap-0.5 h-6">
                       {[0.2, 0.4, 0.6, 0.3, 0.8, 0.5].map((h, i) => (
                          <div 
                            key={i} 
                            className="w-1.5 bg-[#39FF14]/30" 
                            style={{ height: `${h * 100}%` }}
                          />
                       ))}
                    </div>
                 </div>
                 <div className="flex justify-between text-[11px]">
                    <span className="opacity-40">LATENCY</span>
                    <span className="font-bold">42.2ms</span>
                 </div>
                 <div className="flex justify-between text-[11px]">
                    <span className="opacity-40">SYNC_STATUS</span>
                    <span className="text-emerald-500 font-bold">STABLE</span>
                 </div>
              </div>
           </section>

           {/* DECORATIVE TRAFFIC */}
           <section className="glass-panel border-[#39FF14]/10 p-5 hidden xl:block">
              <div className="flex justify-between items-center mb-4">
                <h3 className="text-[9px] font-black uppercase tracking-[0.2em] text-[#39FF14]/40">NETWORK_BURST</h3>
                <Activity size={10} className="text-[#39FF14]/20" />
              </div>
              <div className="flex items-end gap-1 h-12">
                 {Array.from({ length: 20 }).map((_, i) => (
                    <motion.div 
                      key={i}
                      className="flex-1 bg-[#39FF14]/20"
                      animate={{ 
                        height: [
                          `${Math.random() * 100}%`, 
                          `${Math.random() * 100}%`, 
                          `${Math.random() * 100}%`
                        ] 
                      }}
                      transition={{ 
                        duration: 2 + Math.random() * 2, 
                        repeat: Infinity,
                        ease: "linear"
                      }}
                    />
                 ))}
              </div>
           </section>
        </div>

      </main>

      {/* Footer Intel Feed */}
      <AlertNotifications />
      <footer className="fixed bottom-0 left-0 right-0 z-50 p-4">
         <IntelFeed />
      </footer>
    </div>
  );
}
