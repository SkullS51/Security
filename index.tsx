import React, { useState, useCallback, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import { GoogleGenAI, Type } from "@google/genai";
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Server, 
  Terminal, 
  Activity, 
  FileText, 
  Hash, 
  Loader2, 
  Settings, 
  ChevronDown, 
  ChevronUp,
  Globe,
  Database,
  Search
} from 'lucide-react';

// --- Types ---

interface ScanResult {
  source: 'local' | 'gemini';
  status: 'clean' | 'suspicious' | 'malicious' | 'unknown' | 'error';
  confidence: number;
  details: string;
  reasons?: string[];
  meta?: any;
}

interface AnalysisState {
  isAnalyzing: boolean;
  localResult: ScanResult | null;
  geminiResult: ScanResult | null;
  hash: string | null;
}

// --- Configuration ---

const SYSTEM_INSTRUCTION = `
You are ScamShield AI, an advanced cyber-security analyst. 
Your job is to analyze text, emails, or messages for scam indicators.
Look for:
- Urgency or threats
- Financial requests (crypto, gift cards)
- Suspicious links or domains
- Poor grammar or unnatural phrasing
- Impersonation of authority figures

Analyze the provided content and return a JSON object with a verdict.
`;

// --- Main Application ---

const App = () => {
  // Input State
  const [inputText, setInputText] = useState('');
  const [activeTab, setActiveTab] = useState<'text' | 'file' | 'hash'>('text');
  
  // Config State
  const [apiUrl, setApiUrl] = useState('http://localhost:8000');
  const [showSettings, setShowSettings] = useState(false);
  
  // Analysis State
  const [state, setState] = useState<AnalysisState>({
    isAnalyzing: false,
    localResult: null,
    geminiResult: null,
    hash: null,
  });

  // --- Helpers ---

  const calculateHash = async (text: string): Promise<string> => {
    const msgBuffer = new TextEncoder().encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  };

  const checkLocalApi = async (hash: string): Promise<ScanResult> => {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000); // 3s timeout

      const response = await fetch(`${apiUrl}/check-hash`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hash_value: hash }),
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`API Error: ${response.statusText}`);
      }

      const data = await response.json();
      
      if (data.is_threat) {
        return {
          source: 'local',
          status: 'malicious',
          confidence: 100,
          details: 'Match found in local threat database.',
          meta: data
        };
      } else {
        return {
          source: 'local',
          status: 'clean',
          confidence: 100,
          details: 'No match in local database.',
          meta: data
        };
      }
    } catch (e: any) {
      return {
        source: 'local',
        status: 'error',
        confidence: 0,
        details: e.name === 'AbortError' ? 'Connection timed out.' : 'API unreachable. Is the python server running?',
        meta: { error: e.message }
      };
    }
  };

  const checkGemini = async (content: string): Promise<ScanResult> => {
    if (!process.env.API_KEY) {
      return {
        source: 'gemini',
        status: 'error',
        confidence: 0,
        details: 'API Key not configured.',
      };
    }

    try {
      const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
      const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: `Analyze this content for scams: \n\n"${content.substring(0, 10000)}"`, // Limit length
        config: {
          systemInstruction: SYSTEM_INSTRUCTION,
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              isScam: { type: Type.BOOLEAN },
              riskLevel: { type: Type.STRING, enum: ["Safe", "Suspicious", "High Risk"] },
              confidence: { type: Type.INTEGER, description: "0-100" },
              reasons: { type: Type.ARRAY, items: { type: Type.STRING } }
            },
            required: ["isScam", "riskLevel", "confidence", "reasons"]
          }
        }
      });

      const json = JSON.parse(response.text || '{}');
      
      let status: ScanResult['status'] = 'unknown';
      if (json.riskLevel === 'High Risk') status = 'malicious';
      else if (json.riskLevel === 'Suspicious') status = 'suspicious';
      else status = 'clean';

      return {
        source: 'gemini',
        status,
        confidence: json.confidence,
        details: `AI Risk Assessment: ${json.riskLevel}`,
        reasons: json.reasons || [],
        meta: json
      };

    } catch (e: any) {
      console.error(e);
      return {
        source: 'gemini',
        status: 'error',
        confidence: 0,
        details: 'AI Analysis failed.',
        meta: { error: e.message }
      };
    }
  };

  const handleScan = async () => {
    if (!inputText.trim()) return;

    setState(prev => ({ ...prev, isAnalyzing: true, localResult: null, geminiResult: null, hash: null }));

    // 1. Calculate Hash
    let hash = '';
    if (activeTab === 'hash') {
      hash = inputText.trim();
    } else {
      hash = await calculateHash(inputText);
    }
    setState(prev => ({ ...prev, hash }));

    // 2. Run Checks in Parallel
    const localPromise = checkLocalApi(hash);
    
    // Only run Gemini if we have text content (not just a hash)
    const geminiPromise = activeTab !== 'hash' 
      ? checkGemini(inputText) 
      : Promise.resolve<ScanResult>({ 
          source: 'gemini', 
          status: 'unknown', 
          confidence: 0, 
          details: 'Skipped (Direct Hash Input)' 
        });

    const [localRes, geminiRes] = await Promise.all([localPromise, geminiPromise]);

    setState(prev => ({
      ...prev,
      isAnalyzing: false,
      localResult: localRes,
      geminiResult: geminiRes
    }));
  };

  const handleSetupDb = async () => {
    try {
      const res = await fetch(`${apiUrl}/setup`, { method: 'POST' });
      if (res.ok) alert("Database initialized successfully!");
      else alert("Failed to initialize database.");
    } catch (e) {
      alert("Could not connect to API for setup.");
    }
  };

  // --- Render Components ---

  const renderStatusBadge = (result: ScanResult | null) => {
    if (!result) return <span className="text-slate-500">Pending...</span>;
    
    switch (result.status) {
      case 'clean':
        return <span className="inline-flex items-center px-2 py-1 rounded bg-emerald-500/10 text-emerald-500 text-xs font-medium"><CheckCircle size={12} className="mr-1"/> Clean</span>;
      case 'malicious':
        return <span className="inline-flex items-center px-2 py-1 rounded bg-rose-500/10 text-rose-500 text-xs font-medium"><AlertTriangle size={12} className="mr-1"/> THREAT DETECTED</span>;
      case 'suspicious':
        return <span className="inline-flex items-center px-2 py-1 rounded bg-amber-500/10 text-amber-500 text-xs font-medium"><Activity size={12} className="mr-1"/> Suspicious</span>;
      case 'error':
        return <span className="inline-flex items-center px-2 py-1 rounded bg-slate-700 text-slate-400 text-xs font-medium"><Server size={12} className="mr-1"/> Error</span>;
      default:
        return <span className="text-slate-500">Unknown</span>;
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 font-sans selection:bg-emerald-500/30">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur-md sticky top-0 z-10">
        <div className="max-w-5xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="bg-emerald-500/10 p-2 rounded-lg border border-emerald-500/20">
              <Shield className="w-6 h-6 text-emerald-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-white">ScamShield</h1>
              <p className="text-xs text-slate-400 font-mono">Hybrid Threat Intelligence</p>
            </div>
          </div>
          <button 
            onClick={() => setShowSettings(!showSettings)}
            className={`p-2 rounded-md transition-colors ${showSettings ? 'bg-emerald-500/20 text-emerald-400' : 'hover:bg-slate-800 text-slate-400'}`}
          >
            <Settings size={20} />
          </button>
        </div>
      </header>

      {/* Settings Panel */}
      {showSettings && (
        <div className="bg-slate-900 border-b border-slate-800">
          <div className="max-w-5xl mx-auto px-6 py-6 grid gap-6 md:grid-cols-2">
            <div>
              <label className="block text-xs uppercase tracking-wider text-slate-500 mb-2 font-bold">Local API Endpoint</label>
              <div className="flex gap-2">
                <input 
                  type="text" 
                  value={apiUrl} 
                  onChange={(e) => setApiUrl(e.target.value)}
                  className="flex-1 bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-emerald-500/50 transition-colors"
                />
                <button 
                  onClick={handleSetupDb}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm rounded font-medium transition-colors"
                >
                  Init DB
                </button>
              </div>
              <p className="mt-2 text-xs text-slate-500">
                Ensure your local Python server is running and CORS is enabled for this origin.
              </p>
            </div>
          </div>
        </div>
      )}

      <main className="max-w-5xl mx-auto px-6 py-8 grid gap-8 md:grid-cols-[1fr_350px]">
        
        {/* Left Column: Input */}
        <div className="space-y-6">
          
          <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
            {/* Tabs */}
            <div className="flex border-b border-slate-800">
              <button 
                onClick={() => setActiveTab('text')}
                className={`flex-1 py-3 text-sm font-medium flex items-center justify-center gap-2 transition-all ${activeTab === 'text' ? 'bg-slate-800 text-white border-b-2 border-emerald-500' : 'text-slate-500 hover:text-slate-300'}`}
              >
                <FileText size={16} /> Text Content
              </button>
              <button 
                onClick={() => setActiveTab('hash')}
                className={`flex-1 py-3 text-sm font-medium flex items-center justify-center gap-2 transition-all ${activeTab === 'hash' ? 'bg-slate-800 text-white border-b-2 border-emerald-500' : 'text-slate-500 hover:text-slate-300'}`}
              >
                <Hash size={16} /> Direct Hash
              </button>
            </div>

            <div className="p-6">
              <textarea
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                placeholder={activeTab === 'text' ? "Paste suspicious email, message, or text here..." : "Paste SHA-256 hash here..."}
                className="w-full h-64 bg-slate-950 border border-slate-800 rounded-lg p-4 text-slate-300 placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500/50 resize-none font-mono text-sm transition-all"
              />
              
              <div className="mt-4 flex justify-end">
                <button
                  onClick={handleScan}
                  disabled={state.isAnalyzing || !inputText}
                  className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed text-white px-6 py-2 rounded-lg font-semibold shadow-lg shadow-emerald-900/20 flex items-center gap-2 transition-all"
                >
                  {state.isAnalyzing ? <Loader2 className="animate-spin" size={18} /> : <Search size={18} />}
                  Analyze Threat
                </button>
              </div>
            </div>
          </div>

          {/* Detailed Analysis Output */}
          {state.geminiResult && state.geminiResult.status !== 'unknown' && state.geminiResult.source === 'gemini' && (
             <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
                <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                  <Globe className="text-blue-400" size={20}/> AI Semantic Analysis
                </h3>
                
                <div className="space-y-4">
                  <div className="flex items-center justify-between bg-slate-950 p-4 rounded-lg border border-slate-800">
                    <span className="text-slate-400 text-sm">Verdict</span>
                    {renderStatusBadge(state.geminiResult)}
                  </div>

                  {state.geminiResult.reasons && state.geminiResult.reasons.length > 0 && (
                    <div>
                      <h4 className="text-sm font-semibold text-slate-300 mb-2">Risk Indicators</h4>
                      <ul className="space-y-2">
                        {state.geminiResult.reasons.map((reason, idx) => (
                          <li key={idx} className="flex items-start gap-2 text-sm text-slate-400 bg-slate-950/50 p-3 rounded border border-slate-800/50">
                            <AlertTriangle size={14} className="mt-0.5 text-amber-500 shrink-0" />
                            {reason}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  <div className="bg-slate-950/30 p-3 rounded border border-slate-800/30 text-xs text-slate-500 text-center">
                     Powered by Gemini 2.5 Flash • Confidence: {state.geminiResult.confidence}%
                  </div>
                </div>
             </div>
          )}
        </div>

        {/* Right Column: Status Cards */}
        <div className="space-y-4">
          
          {/* Hash Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
            <div className="flex items-center gap-2 text-slate-400 mb-2">
              <Hash size={16} />
              <span className="text-xs font-bold uppercase tracking-wider">Fingerprint</span>
            </div>
            <div className="font-mono text-xs text-emerald-400 break-all bg-slate-950 p-2 rounded border border-slate-800/50">
              {state.hash || 'WAITING FOR INPUT...'}
            </div>
          </div>

          {/* Local DB Result */}
          <div className={`bg-slate-900 border rounded-lg p-4 transition-colors ${state.localResult?.status === 'malicious' ? 'border-rose-500/50 bg-rose-950/10' : 'border-slate-800'}`}>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2 text-slate-300">
                <Database size={16} />
                <span className="font-semibold text-sm">Local Database</span>
              </div>
              {renderStatusBadge(state.localResult)}
            </div>
            <p className="text-sm text-slate-400">
              {state.localResult?.details || 'Checks against your local API threat list.'}
            </p>
            {state.localResult?.status === 'error' && (
               <p className="text-xs text-rose-400 mt-2">
                 Check if backend is running on {apiUrl}
               </p>
            )}
          </div>

          {/* Gemini Status Summary */}
          <div className={`bg-slate-900 border rounded-lg p-4 transition-colors ${state.geminiResult?.status === 'malicious' ? 'border-rose-500/50 bg-rose-950/10' : 'border-slate-800'}`}>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2 text-slate-300">
                <Activity size={16} />
                <span className="font-semibold text-sm">AI Heuristics</span>
              </div>
              {renderStatusBadge(state.geminiResult)}
            </div>
            <p className="text-sm text-slate-400">
              {state.geminiResult?.details || 'Deep learning analysis of content patterns.'}
            </p>
          </div>

        </div>
      </main>
    </div>
  );
};

const root = createRoot(document.getElementById('root')!);
root.render(<App />);