import React, { useEffect, useState } from 'react';
import { 
  db, 
  collection, 
  query, 
  where, 
  onSnapshot, 
  orderBy, 
  limit, 
  handleFirestoreError, 
  OperationType,
  Timestamp,
  deleteDoc,
  doc
} from '../lib/firebase';
import { useAuth } from './AuthProvider';
import { Shield, ExternalLink, Calendar, Trash2, AlertTriangle, CheckCircle } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

interface ScanReport {
  id: string;
  target: string;
  classification: string;
  threatScore: number;
  userId: string;
  createdAt: any;
}

export function ScanHistory({ onSelect }: { onSelect: (report: any) => void }) {
  const { user } = useAuth();
  const [reports, setReports] = useState<ScanReport[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!user) return;

    const reportsRef = collection(db, 'scanReports');
    const q = query(
      reportsRef,
      where('userId', '==', user.uid),
      orderBy('createdAt', 'desc'),
      limit(20)
    );

    const unsubscribe = onSnapshot(q, (snapshot) => {
      const data = snapshot.docs.map(doc => ({
        id: doc.id,
        ...doc.data()
      })) as ScanReport[];
      setReports(data);
      setLoading(false);
    }, (error) => {
      handleFirestoreError(error, OperationType.LIST, 'scanReports');
    });

    return () => unsubscribe();
  }, [user]);

  const handleDelete = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    try {
      await deleteDoc(doc(db, 'scanReports', id));
    } catch (err) {
      handleFirestoreError(err, OperationType.DELETE, `scanReports/${id}`);
    }
  };

  const getStatusIcon = (classification: string) => {
    switch (classification) {
      case 'Safe': return <CheckCircle className="text-[#39FF14]" size={14} />;
      case 'Suspicious': return <AlertTriangle className="text-amber-500" size={14} />;
      case 'Phishing': 
      case 'Malicious': return <AlertTriangle className="text-red-500" size={14} />;
      default: return <Shield size={14} />;
    }
  };

  if (!user) return null;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-[#39FF14] flex items-center gap-2">
          <Calendar size={12} className="text-blue-400" /> THREAT_HISTORY_LOG
        </h3>
        <span className="text-[8px] opacity-30 uppercase tracking-widest">{reports.length} RECORDS_LOADED</span>
      </div>

      <div className="space-y-2 max-h-[400px] overflow-y-auto custom-scrollbar pr-2">
        <AnimatePresence initial={false}>
          {reports.map((report) => (
            <motion.div
              layout
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 10 }}
              key={report.id}
              onClick={() => onSelect(report)}
              className="bg-black/80 border border-[#39FF14]/10 p-3 hover:border-[#39FF14]/40 cursor-pointer group transition-all"
            >
              <div className="flex justify-between items-start mb-2">
                <div className="flex items-center gap-2">
                  {getStatusIcon(report.classification)}
                  <span className="text-[11px] font-bold truncate max-w-[150px]">{report.target}</span>
                </div>
                <button 
                  onClick={(e) => handleDelete(e, report.id)}
                  className="opacity-0 group-hover:opacity-100 p-1 text-red-500/40 hover:text-red-500 transition-all"
                >
                  <Trash2 size={12} />
                </button>
              </div>
              <div className="flex justify-between items-center">
                <div className="flex gap-2 text-[8px] opacity-40 uppercase">
                  <span>{report.createdAt instanceof Timestamp ? report.createdAt.toDate().toLocaleDateString() : 'RECENT'}</span>
                  <span>{report.classification}</span>
                </div>
                <div className="text-[10px] font-black italic">
                  SCORE: <span className={
                    report.threatScore < 30 ? "text-[#39FF14]" :
                    report.threatScore < 70 ? "text-amber-500" : "text-red-500"
                  }>{report.threatScore}</span>
                </div>
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
        
        {!loading && reports.length === 0 && (
          <div className="text-center py-12 border border-dashed border-[#39FF14]/10">
            <p className="text-[9px] opacity-20 uppercase tracking-widest">No scan history recorded</p>
          </div>
        )}
      </div>
    </div>
  );
}
