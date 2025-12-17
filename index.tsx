import React, { useState, useCallback, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import { GoogleGenAI, Type } from "@google/genai";
import { Analytics } from "@vercel/analytics/react";
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
  Search,
  Upload,
  Smartphone,
  Wifi,
  WifiOff
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

const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

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
  const [uploadError, setUploadError] = useState<string | null>(null);
  
  // Config State
  const [apiUrl, setApiUrl] = useState('http://localhost:8000');
  const [dbMode, setDbMode] = useState<'browser' | 'server'>('browser'); // Default to browser for tablet/mobile
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

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    setUploadError(null);
    const file = e.target.files?.[0];
    if (!file) return;

    // Check File Size
    if (file.size > MAX_FILE_SIZE) {
      setUploadError(`File is too large (${(file.size / 1024 / 1024).toFixed(2)}MB). Limit is 5MB.`);
      e.target.value = '';
      return;
    }

    const reader = new FileReader();
    
    reader.onload = (event) => {
      const text = event.target?.result;
      
      if (typeof text !== 'string') {
        setUploadError("Unable to read file content as text.");
        return;
      }

      if (text.includes('\0')) {
        setUploadError("File appears to be binary. Please upload text-based files (.txt, .eml, .json, etc).");
        return;
      }

      setInputText(text);
      setActiveTab('text');
    };

    reader.onerror = () => {
      setUploadError("Error reading file. It may be corrupted or unreadable.");
    };

    try {
      reader.readAsText(file);
    } catch (err) {
      setUploadError("Failed to initiate file upload.");
      console.error(err);
    }
    
    e.target.value = '';
  };

  const checkLocalApi = async (hash: string): Promise<ScanResult> => {
    // Mode 1: Browser/Tablet (LocalStorage)
    if (dbMode === 'browser') {
      try {
        // Simulate async lookup
        await new Promise(resolve => setTimeout(resolve, 500));
        
        const storedDb = localStorage.getItem('scamshield_threats');
        const db = storedDb ? JSON.parse(storedDb) : {};
        const match = db[hash];

        if (match) {
          return {
            source: 'local',
            status: 'malicious',
            confidence: 100,
            details: `Match found in on-device database: ${match.label || 'Known Threat'}`,
            meta: match
          };
        } else {
          return {
            source: 'local',
            status: 'clean',
            confidence: 100,
            details: 'No match in on-device database.',
            meta: null
          };
        }
      } catch (e: any) {
        return {
          source: 'local',
          status: 'error',
          confidence: 0,
          details: 'Failed to access device storage.',
          meta: { error: e.message }
        };
      }
    }

    // Mode 2: External Server (Python API)
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
          details: 'Match found in remote threat database.',
          meta: data
        };
      } else {
        return {
          source: 'local',
          status: 'clean',
          confidence: 100,
          details: 'No match in remote database.',
          meta: data
        };
      }
    } catch (e: any) {
      return {
        source: 'local',
        status: 'error',
        confidence: 0,
        details: e.name === 'AbortError' ? 'Connection timed out.' : 'Remote API unreachable.',
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
        contents: `Analyze this content for scams: \n\n"${content.substring(0, 10000)}"`,
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
    if (dbMode === 'browser') {
      // Setup Browser DB with test data
      const defaults = {
        // "scam"
        "063e52109277083040436894565706911299967650766324600676442653303c": { label: "Test Signature: 'scam'", severity: "high" },
        // "virus"
        "d8981f2162601974d6f8d38787f7300c7e2b793666d997d983446045862d2952": { label: "Test Signature: 'virus'", severity: "critical" },
      };
      localStorage.setItem('scamshield_threats', JSON.stringify(defaults));
      alert("On-device database initialized. Try scanning the text 'scam' or 'virus'.");
    } else {
      // Setup Server DB
      try {
        const res = await fetch(`${apiUrl}/setup`, { method: 'POST' });
        if (res.ok) alert("Server database initialized successfully!");
        else alert("Failed to initialize server database.");
      } catch (e) {
        alert("Could not connect to API for setup.");
      }
    }
  };

  const handleTabChange = (tab: 'text' | 'file' | 'hash') => {
    setActiveTab(tab);
    setUploadError(null);
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
        <div className="bg-slate-900 border-b border-slate-800 animate-in slide-in-from-top-2">
          <div className="max-w-5xl mx-auto px-6 py-6 grid gap-6 md:grid-cols-2">
            
            {/* Database Mode Selection */}
            <div>
              <label className="block text-xs uppercase tracking-wider text-slate-500 mb-2 font-bold">Threat Database Mode</label>
              <div className="flex bg-slate-950 p-1 rounded-lg border border-slate-800 mb-4">
                <button
                  onClick={() => setDbMode('browser')}
                  className={`flex-1 py-2 px-3 text-sm font-medium rounded-md flex items-center justify-center gap-2 transition-all ${dbMode === 'browser' ? 'bg-slate-800 text-white shadow' : 'text-slate-400 hover:text-slate-200'}`}
                >
                  <Smartphone size={14} /> On-Device (Tablet)
                </button>
                <button
                  onClick={() => setDbMode('server')}
                  className={`flex-1 py-2 px-3 text-sm font-medium rounded-md flex items-center justify-center gap-2 transition-all ${dbMode === 'server' ? 'bg-slate-800 text-white shadow' : 'text-slate-400 hover:text-slate-200'}`}
                >
                  <Server size={14} /> Remote Server
                </button>
              </div>

              {dbMode === 'server' ? (
                <div>
                   <label className="block text-xs text-slate-500 mb-2">Remote API Endpoint</label>
                   <div className="flex gap-2">
                    <input 
                      type="text" 
                      value={apiUrl} 
                      onChange={(e) => setApiUrl(e.target.value)}
                      className="flex-1 bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-emerald-500/50"
                    />
                    <button onClick={handleSetupDb} className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm rounded transition-colors">Test</button>
                   </div>
                </div>
              ) : (
                <div className="bg-emerald-500/5 border border-emerald-500/10 rounded p-3">
                  <p className="text-xs text-emerald-400 mb-2 flex items-center gap-2">
                    <CheckCircle size={12}/> Running locally. No server required.
                  </p>
                  <button 
                    onClick={handleSetupDb}
                    className="w-full py-2 bg-emerald-600/10 hover:bg-emerald-600/20 text-emerald-400 border border-emerald-500/20 text-sm rounded font-medium transition-colors"
                  >
                    Initialize Test Database
                  </button>
                </div>
              )}
            </div>

            <div className="text-xs text-slate-500">
              <p className="mb-2"><strong className="text-slate-400">On-Device Mode:</strong> Uses local browser storage to check content hashes. Ideal for tablets and offline usage.</p>
              <p><strong className="text-slate-400">Remote Server Mode:</strong> Connects to a Python backend for enterprise-grade threat lookup.</p>
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
                onClick={() => handleTabChange('text')}
                className={`flex-1 py-3 text-sm font-medium flex items-center justify-center gap-2 transition-all ${activeTab === 'text' ? 'bg-slate-800 text-white border-b-2 border-emerald-500' : 'text-slate-500 hover:text-slate-300'}`}
              >
                <FileText size={16} /> Text Content
              </button>
              <button 
                onClick={() => handleTabChange('file')}
                className={`flex-1 py-3 text-sm font-medium flex items-center justify-center gap-2 transition-all ${activeTab === 'file' ? 'bg-slate-800 text-white border-b-2 border-emerald-500' : 'text-slate-500 hover:text-slate-300'}`}
              >
                <Upload size={16} /> Upload File
              </button>
              <button 
                onClick={() => handleTabChange('hash')}
                className={`flex-1 py-3 text-sm font-medium flex items-center justify-center gap-2 transition-all ${activeTab === 'hash' ? 'bg-slate-800 text-white border-b-2 border-emerald-500' : 'text-slate-500 hover:text-slate-300'}`}
              >
                <Hash size={16} /> Direct Hash
              </button>
            </div>

            <div className="p-6">
              {activeTab === 'file' ? (
                <div className={`w-full h-64 border-2 border-dashed rounded-lg flex flex-col items-center justify-center bg-slate-950/50 transition-colors group ${uploadError ? 'border-rose-500/50 bg-rose-950/10' : 'border-slate-800 hover:bg-slate-900/50'}`}>
                  {uploadError ? (
                    <div className="flex flex-col items-center text-center p-6 animate-in fade-in zoom-in duration-300">
                      <div className="bg-rose-500/10 p-4 rounded-full mb-4 border border-rose-500/20">
                        <AlertTriangle size={24} className="text-rose-500" />
                      </div>
                      <p className="text-rose-400 font-medium mb-1">Upload Failed</p>
                      <p className="text-rose-300/70 text-sm mb-6 max-w-xs">{uploadError}</p>
                      <button 
                        onClick={() => setUploadError(null)}
                        className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm rounded transition-colors border border-slate-700"
                      >
                        Try Again
                      </button>
                    </div>
                  ) : (
                    <>
                      <div className="bg-slate-900 p-4 rounded-full mb-4 group-hover:bg-slate-800 transition-colors border border-slate-800">
                        <Upload size={24} className="text-emerald-500" />
                      </div>
                      <p className="text-slate-300 font-medium mb-1">Upload a file to scan</p>
                      <p className="text-slate-500 text-xs mb-6">Supported: .txt, .eml, .msg, .log, .json (Max 5MB)</p>
                      <label className="cursor-pointer relative group">
                        <div className="absolute -inset-0.5 bg-gradient-to-r from-emerald-600 to-teal-600 rounded-lg blur opacity-50 group-hover:opacity-100 transition duration-200"></div>
                        <span className="relative block bg-slate-900 text-white px-6 py-2.5 rounded-lg text-sm font-semibold border border-slate-800 hover:bg-slate-800 transition-all flex items-center gap-2">
                          <FileText size={14} className="text-emerald-400"/> Browse Files
                        </span>
                        <input 
                          type="file" 
                          className="hidden" 
                          accept=".txt,.eml,.msg,.log,.json"
                          onChange={handleFileUpload}
                        />
                      </label>
                    </>
                  )}
                </div>
              ) : (
                <textarea
                  value={inputText}
                  onChange={(e) => setInputText(e.target.value)}
                  placeholder={activeTab === 'text' ? "Paste suspicious email, message, or text here..." : "Paste SHA-256 hash here..."}
                  className="w-full h-64 bg-slate-950 border border-slate-800 rounded-lg p-4 text-slate-300 placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500/50 resize-none font-mono text-sm transition-all"
                />
              )}
              
              <div className="mt-4 flex justify-end">
                <button
                  onClick={handleScan}
                  disabled={state.isAnalyzing || !inputText || !!uploadError}
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

          {/* Local/Device DB Result */}
          <div className={`bg-slate-900 border rounded-lg p-4 transition-colors ${state.localResult?.status === 'malicious' ? 'border-rose-500/50 bg-rose-950/10' : 'border-slate-800'}`}>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2 text-slate-300">
                {dbMode === 'browser' ? <Smartphone size={16}/> : <Database size={16} />}
                <span className="font-semibold text-sm">
                  {dbMode === 'browser' ? 'On-Device Database' : 'Remote Database'}
                </span>
              </div>
              {renderStatusBadge(state.localResult)}
            </div>
            <p className="text-sm text-slate-400">
              {state.localResult?.details || 'Checks against known threat signatures.'}
            </p>
            {state.localResult?.status === 'error' && dbMode === 'server' && (
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
root.render(<><App /><Analytics /></>);