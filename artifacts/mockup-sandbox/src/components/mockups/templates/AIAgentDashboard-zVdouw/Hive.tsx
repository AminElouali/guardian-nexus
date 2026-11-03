import React, { useState, useEffect, useRef } from 'react';
import { 
  Activity, 
  Bot, 
  Box, 
  CheckCircle2, 
  ChevronRight, 
  CircleDashed, 
  Clock, 
  Cpu, 
  Database, 
  Filter, 
  FolderGit2, 
  LayoutDashboard, 
  LogOut, 
  MoreHorizontal, 
  MoreVertical, 
  Play, 
  Plus, 
  Power, 
  Search, 
  Settings, 
  SquareTerminal, 
  StopCircle, 
  Terminal, 
  X, 
  Zap,
  Globe,
  Lock,
  PauseCircle,
  AlertCircle
} from 'lucide-react';

// --- MOCK DATA ---
const INITIAL_AGENTS = [
  {
    id: 'ag-1',
    name: 'Data Scraper - Financials',
    description: 'Crawls SEC filings and extracts key financial metrics into the data warehouse.',
    status: 'active',
    model: 'gpt-4-turbo',
    lastRun: '10 mins ago',
    successRate: 98,
    tags: ['ETL', 'Finance']
  },
  {
    id: 'ag-2',
    name: 'Customer Support Triager',
    description: 'Classifies incoming support tickets and routes them to the appropriate human agent.',
    status: 'paused',
    model: 'claude-3-opus',
    lastRun: '2 hours ago',
    successRate: 92,
    tags: ['NLP', 'Support']
  },
  {
    id: 'ag-3',
    name: 'Code Review Bot',
    description: 'Analyzes pull requests for security vulnerabilities and style guide violations.',
    status: 'active',
    model: 'gpt-4',
    lastRun: 'Just now',
    successRate: 85,
    tags: ['DevOps', 'Security']
  },
  {
    id: 'ag-4',
    name: 'Marketing Copy Generator',
    description: 'Generates weekly newsletter content based on product updates and blog posts.',
    status: 'error',
    model: 'gpt-3.5-turbo',
    lastRun: '1 day ago',
    successRate: 60,
    tags: ['Content', 'Marketing']
  },
  {
    id: 'ag-5',
    name: 'Database Optimizer',
    description: 'Periodically runs EXPLAIN on slow queries and suggests indexes.',
    status: 'active',
    model: 'gpt-4-turbo',
    lastRun: '4 hours ago',
    successRate: 100,
    tags: ['Infrastructure', 'DB']
  },
  {
    id: 'ag-6',
    name: 'Social Media Monitor',
    description: 'Tracks brand mentions across Twitter and Reddit, performing sentiment analysis.',
    status: 'paused',
    model: 'claude-3-sonnet',
    lastRun: '3 days ago',
    successRate: 95,
    tags: ['Social', 'Analytics']
  }
];

const INITIAL_LOGS: Record<string, { timestamp: string; level: 'info'|'warn'|'error'|'success'; message: string }[]> = {
  'ag-1': [
    { timestamp: '10:05:22', level: 'info', message: 'Initialized scraper module.' },
    { timestamp: '10:05:25', level: 'info', message: 'Fetching index for AAPL...' },
    { timestamp: '10:05:28', level: 'success', message: 'Successfully parsed 10-K document.' },
  ],
  'ag-3': [
    { timestamp: '11:42:01', level: 'info', message: 'Webhook received for PR #4022.' },
    { timestamp: '11:42:05', level: 'info', message: 'Cloning repository...' },
    { timestamp: '11:42:15', level: 'warn', message: 'Found 3 linting warnings in src/utils.ts' },
  ],
  'ag-4': [
    { timestamp: '08:00:00', level: 'info', message: 'Starting scheduled job: Weekly Newsletter.' },
    { timestamp: '08:00:05', level: 'info', message: 'Gathering inputs from Notion API...' },
    { timestamp: '08:00:10', level: 'error', message: 'Failed to connect to Notion API. Rate limit exceeded.' },
  ]
};

const STREAMING_MESSAGES = [
  "Connecting to execution environment...",
  "Loading model weights into VRAM...",
  "Fetching required context from vector DB...",
  "Executing inference step 1/4...",
  "Executing inference step 2/4...",
  "Executing inference step 3/4...",
  "Executing inference step 4/4...",
  "Formatting output schema...",
  "Validating response against constraints...",
  "Writing results to destination table...",
  "Cleaning up execution context...",
  "Run completed successfully."
];

// --- HELPER COMPONENTS ---
function Badge({ children, variant = 'default', className = '' }: any) {
  const variants: any = {
    default: 'bg-zinc-800 text-zinc-300',
    active: 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20',
    paused: 'bg-amber-500/10 text-amber-400 border border-amber-500/20',
    error: 'bg-red-500/10 text-red-400 border border-red-500/20',
    outline: 'border border-zinc-700 text-zinc-400'
  };
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${variants[variant]} ${className}`}>
      {children}
    </span>
  );
}

// --- MAIN APP COMPONENT ---
export default function Hive() {
  const [activeNav, setActiveNav] = useState('agents');
  const [agents, setAgents] = useState(INITIAL_AGENTS);
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null);
  const [logs, setLogs] = useState(INITIAL_LOGS);
  const [runningAgents, setRunningAgents] = useState<Record<string, boolean>>({});
  
  const logEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll logs
  useEffect(() => {
    if (logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, selectedAgentId]);

  const toggleAgentStatus = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setAgents(prev => prev.map(a => {
      if (a.id === id) {
        return { ...a, status: a.status === 'active' ? 'paused' : 'active' };
      }
      return a;
    }));
  };

  const handleRunAgent = (id: string) => {
    if (runningAgents[id]) return; // Already running
    
    setRunningAgents(prev => ({ ...prev, [id]: true }));
    
    // Initialize empty log if none exists
    setLogs(prev => ({
      ...prev,
      [id]: prev[id] || []
    }));

    let step = 0;
    const interval = setInterval(() => {
      if (step >= STREAMING_MESSAGES.length) {
        clearInterval(interval);
        setRunningAgents(prev => ({ ...prev, [id]: false }));
        // Update last run
        setAgents(prev => prev.map(a => a.id === id ? { ...a, lastRun: 'Just now', status: a.status === 'error' ? 'active' : a.status } : a));
        return;
      }
      
      const msg = STREAMING_MESSAGES[step];
      const level = step === STREAMING_MESSAGES.length - 1 ? 'success' : 'info';
      
      const now = new Date();
      const timeStr = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}`;
      
      setLogs(prev => ({
        ...prev,
        [id]: [...(prev[id] || []), { timestamp: timeStr, level: level as any, message: msg }]
      }));
      
      step++;
    }, 600); // Add a log every 600ms
  };

  const filteredAgents = agents.filter(a => {
    const matchesFilter = filter === 'all' || a.status === filter;
    const matchesSearch = a.name.toLowerCase().includes(search.toLowerCase()) || a.description.toLowerCase().includes(search.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  const selectedAgent = agents.find(a => a.id === selectedAgentId);
  const currentLogs = selectedAgentId ? (logs[selectedAgentId] || []) : [];

  return (
    <div className="w-full h-full bg-[#0c0c0e] text-zinc-100 flex overflow-hidden font-['Inter',sans-serif] selection:bg-indigo-500/30">
      
      {/* SIDEBAR */}
      <div className="w-64 border-r border-zinc-800/50 bg-[#0c0c0e] flex flex-col flex-shrink-0 z-20">
        <div className="h-16 flex items-center px-6 border-b border-zinc-800/50">
          <div className="flex items-center gap-2 text-indigo-400">
            <Box className="w-5 h-5" />
            <span className="font-bold text-lg tracking-tight text-white">Hive</span>
          </div>
        </div>
        
        <div className="flex-1 py-6 px-4 space-y-8">
          <div className="space-y-1">
            <div className="px-2 text-xs font-semibold text-zinc-500 mb-2 uppercase tracking-wider">Menu</div>
            <button 
              onClick={() => setActiveNav('dashboard')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${activeNav === 'dashboard' ? 'bg-zinc-800/50 text-white' : 'text-zinc-400 hover:text-white hover:bg-zinc-800/30'}`}
            >
              <LayoutDashboard className="w-4 h-4" /> Dashboard
            </button>
            <button 
              onClick={() => setActiveNav('agents')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${activeNav === 'agents' ? 'bg-zinc-800/50 text-white' : 'text-zinc-400 hover:text-white hover:bg-zinc-800/30'}`}
            >
              <Bot className="w-4 h-4" /> Agents
              <span className="ml-auto bg-zinc-800 text-zinc-300 py-0.5 px-2 rounded-full text-xs">{agents.length}</span>
            </button>
            <button 
              onClick={() => setActiveNav('workflows')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${activeNav === 'workflows' ? 'bg-zinc-800/50 text-white' : 'text-zinc-400 hover:text-white hover:bg-zinc-800/30'}`}
            >
              <FolderGit2 className="w-4 h-4" /> Workflows
            </button>
            <button 
              onClick={() => setActiveNav('evaluations')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${activeNav === 'evaluations' ? 'bg-zinc-800/50 text-white' : 'text-zinc-400 hover:text-white hover:bg-zinc-800/30'}`}
            >
              <Activity className="w-4 h-4" /> Evaluations
            </button>
          </div>

          <div className="space-y-1">
            <div className="px-2 text-xs font-semibold text-zinc-500 mb-2 uppercase tracking-wider">Resources</div>
            <button className="w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium text-zinc-400 hover:text-white hover:bg-zinc-800/30 transition-colors">
              <Database className="w-4 h-4" /> Vector Stores
            </button>
            <button className="w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium text-zinc-400 hover:text-white hover:bg-zinc-800/30 transition-colors">
              <Globe className="w-4 h-4" /> Tools & API
            </button>
            <button className="w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium text-zinc-400 hover:text-white hover:bg-zinc-800/30 transition-colors">
              <Lock className="w-4 h-4" /> Secrets
            </button>
          </div>
        </div>

        <div className="p-4 border-t border-zinc-800/50">
          <button className="w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium text-zinc-400 hover:text-white hover:bg-zinc-800/30 transition-colors">
            <Settings className="w-4 h-4" /> Settings
          </button>
          <div className="mt-4 flex items-center gap-3 px-3 py-2">
            <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-indigo-500 to-purple-500 flex items-center justify-center text-sm font-bold text-white shadow-inner">
              K
            </div>
            <div className="flex flex-col">
              <span className="text-sm font-medium text-white">Kirk</span>
              <span className="text-xs text-zinc-500">Acme Corp</span>
            </div>
          </div>
        </div>
      </div>

      {/* MAIN CONTENT AREA */}
      <div className="flex-1 flex flex-col relative overflow-hidden bg-[#0c0c0e]">
        
        {activeNav !== 'agents' ? (
          <div className="flex-1 flex flex-col items-center justify-center text-zinc-500">
            <Bot className="w-16 h-16 mb-4 opacity-20" />
            <h2 className="text-xl font-semibold text-zinc-300">Section not implemented</h2>
            <p className="text-sm mt-2">Navigate to Agents to see the interactive prototype.</p>
            <button 
              onClick={() => setActiveNav('agents')}
              className="mt-6 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-md text-sm font-medium transition-colors"
            >
              Go to Agents
            </button>
          </div>
        ) : (
          <>
            {/* TOP BAR */}
            <div className="h-16 flex items-center justify-between px-8 border-b border-zinc-800/50 bg-[#0c0c0e]/80 backdrop-blur-sm z-10 sticky top-0 flex-shrink-0">
              <h1 className="text-xl font-semibold text-white">Agents</h1>
              
              <div className="flex items-center gap-4">
                <div className="relative group">
                  <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500 group-focus-within:text-indigo-400 transition-colors" />
                  <input 
                    type="text" 
                    placeholder="Search agents..." 
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    className="bg-zinc-900/50 border border-zinc-800 focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/50 rounded-md pl-9 pr-4 py-1.5 text-sm text-zinc-200 w-64 transition-all outline-none"
                  />
                </div>
                
                <button className="flex items-center gap-2 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-md text-sm font-medium transition-all shadow-[0_0_15px_-3px_rgba(79,70,229,0.4)]">
                  <Plus className="w-4 h-4" /> New Agent
                </button>
              </div>
            </div>

            {/* CONTENT GRID */}
            <div className={`flex-1 overflow-y-auto p-8 flex transition-all duration-300 ${selectedAgentId ? 'mr-[400px]' : ''}`}>
              <div className="max-w-5xl mx-auto w-full">
                
                {/* FILTERS */}
                <div className="flex items-center gap-2 mb-6">
                  <Filter className="w-4 h-4 text-zinc-500 mr-2" />
                  {['all', 'active', 'paused', 'error'].map(f => (
                    <button
                      key={f}
                      onClick={() => setFilter(f)}
                      className={`px-3 py-1 rounded-full text-xs font-medium capitalize transition-colors ${
                        filter === f 
                          ? 'bg-zinc-800 text-white' 
                          : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50'
                      }`}
                    >
                      {f}
                    </button>
                  ))}
                </div>

                {/* CARDS */}
                <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4 pb-12">
                  {filteredAgents.length === 0 ? (
                    <div className="col-span-full py-12 flex flex-col items-center justify-center text-zinc-500 border border-dashed border-zinc-800 rounded-lg">
                      <Search className="w-8 h-8 mb-3 opacity-20" />
                      <p>No agents found matching criteria.</p>
                      <button onClick={() => {setFilter('all'); setSearch('');}} className="mt-2 text-indigo-400 text-sm hover:underline">Clear filters</button>
                    </div>
                  ) : (
                    filteredAgents.map(agent => (
                      <div 
                        key={agent.id}
                        onClick={() => setSelectedAgentId(agent.id)}
                        className={`group bg-zinc-900/40 border ${selectedAgentId === agent.id ? 'border-indigo-500/50 ring-1 ring-indigo-500/20' : 'border-zinc-800/80 hover:border-zinc-700'} rounded-xl p-5 cursor-pointer transition-all hover:bg-zinc-900/80 flex flex-col`}
                      >
                        <div className="flex justify-between items-start mb-3">
                          <div className="flex items-center gap-3">
                            <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                              agent.status === 'active' ? 'bg-emerald-500/10 text-emerald-400' : 
                              agent.status === 'paused' ? 'bg-amber-500/10 text-amber-400' : 
                              'bg-red-500/10 text-red-400'
                            }`}>
                              <Bot className="w-4 h-4" />
                            </div>
                            <div>
                              <h3 className="text-sm font-semibold text-zinc-100 group-hover:text-indigo-300 transition-colors">{agent.name}</h3>
                              <div className="flex items-center gap-1.5 mt-0.5">
                                <Badge variant={agent.status} className="!text-[10px] !px-1.5 !py-0">
                                  {agent.status.toUpperCase()}
                                </Badge>
                                <span className="text-xs text-zinc-500 flex items-center gap-1">
                                  <Cpu className="w-3 h-3" /> {agent.model}
                                </span>
                              </div>
                            </div>
                          </div>
                          
                          {/* Toggle Switch */}
                          <button 
                            onClick={(e) => toggleAgentStatus(agent.id, e)}
                            className={`w-9 h-5 rounded-full relative transition-colors ${agent.status === 'active' ? 'bg-emerald-500/20' : 'bg-zinc-800'}`}
                          >
                            <div className={`absolute top-1 w-3 h-3 rounded-full bg-white transition-all ${agent.status === 'active' ? 'left-5 bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]' : 'left-1 bg-zinc-500'}`} />
                          </button>
                        </div>
                        
                        <p className="text-sm text-zinc-400 line-clamp-2 mb-4 flex-1">
                          {agent.description}
                        </p>
                        
                        <div className="flex flex-wrap gap-2 mb-4">
                          {agent.tags.map(tag => (
                            <Badge key={tag} variant="outline" className="!text-[10px]">{tag}</Badge>
                          ))}
                        </div>
                        
                        <div className="pt-3 border-t border-zinc-800/50 flex items-center justify-between text-xs text-zinc-500">
                          <div className="flex items-center gap-1.5">
                            <Clock className="w-3.5 h-3.5" />
                            <span>Run: {agent.lastRun}</span>
                          </div>
                          <div className="flex items-center gap-1.5">
                            <Zap className="w-3.5 h-3.5 text-amber-500/70" />
                            <span>{agent.successRate}% Success</span>
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </>
        )}

      </div>

      {/* RIGHT SIDE PANEL (Details & Logs) */}
      <div 
        className={`absolute top-0 right-0 w-[400px] h-full bg-[#121215] border-l border-zinc-800 shadow-2xl transition-transform duration-300 ease-in-out flex flex-col z-30 ${selectedAgentId && activeNav === 'agents' ? 'translate-x-0' : 'translate-x-full'}`}
      >
        {selectedAgent && (
          <>
            <div className="h-16 flex items-center justify-between px-6 border-b border-zinc-800/50 bg-[#121215] flex-shrink-0">
              <h2 className="text-base font-semibold text-white truncate pr-4">{selectedAgent.name}</h2>
              <button 
                onClick={() => setSelectedAgentId(null)}
                className="p-1.5 text-zinc-500 hover:text-white hover:bg-zinc-800 rounded-md transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto">
              <div className="p-6 border-b border-zinc-800/50">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2">
                    <Badge variant={selectedAgent.status}>{selectedAgent.status.toUpperCase()}</Badge>
                    <span className="text-xs text-zinc-400 font-mono">{selectedAgent.id}</span>
                  </div>
                  
                  <div className="flex items-center gap-2">
                    <button className="p-1.5 text-zinc-400 hover:text-white bg-zinc-800/50 hover:bg-zinc-700 rounded-md transition-colors" title="Settings">
                      <Settings className="w-4 h-4" />
                    </button>
                    <button 
                      onClick={() => handleRunAgent(selectedAgent.id)}
                      disabled={runningAgents[selectedAgent.id]}
                      className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-all ${
                        runningAgents[selectedAgent.id] 
                          ? 'bg-zinc-800 text-zinc-500 cursor-not-allowed'
                          : 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-[0_0_10px_-2px_rgba(79,70,229,0.3)]'
                      }`}
                    >
                      {runningAgents[selectedAgent.id] ? (
                        <><CircleDashed className="w-4 h-4 animate-spin" /> Running...</>
                      ) : (
                        <><Play className="w-4 h-4" /> Run Now</>
                      )}
                    </button>
                  </div>
                </div>
                
                <p className="text-sm text-zinc-400 mb-6">{selectedAgent.description}</p>
                
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-zinc-900/50 p-3 rounded-lg border border-zinc-800/50">
                    <div className="text-xs text-zinc-500 mb-1">Model</div>
                    <div className="text-sm font-medium text-zinc-200">{selectedAgent.model}</div>
                  </div>
                  <div className="bg-zinc-900/50 p-3 rounded-lg border border-zinc-800/50">
                    <div className="text-xs text-zinc-500 mb-1">Success Rate</div>
                    <div className="text-sm font-medium text-emerald-400">{selectedAgent.successRate}%</div>
                  </div>
                </div>
              </div>

              {/* LOGS SECTION */}
              <div className="flex flex-col h-[calc(100%-250px)]">
                <div className="px-6 py-4 flex items-center justify-between border-b border-zinc-800/50">
                  <div className="flex items-center gap-2 text-sm font-medium text-zinc-200">
                    <Terminal className="w-4 h-4 text-zinc-500" /> Execution Logs
                  </div>
                  <button 
                    onClick={() => setLogs(prev => ({ ...prev, [selectedAgent.id]: [] }))}
                    className="text-xs text-zinc-500 hover:text-zinc-300"
                  >
                    Clear
                  </button>
                </div>
                
                <div className="flex-1 bg-[#0a0a0c] p-4 overflow-y-auto font-mono text-[11px] leading-relaxed">
                  {currentLogs.length === 0 ? (
                    <div className="text-zinc-600 italic h-full flex flex-col items-center justify-center opacity-50">
                      <SquareTerminal className="w-8 h-8 mb-2" />
                      No logs available.
                    </div>
                  ) : (
                    <div className="space-y-1.5">
                      {currentLogs.map((log, i) => (
                        <div key={i} className="flex gap-3 hover:bg-zinc-900/50 py-0.5 px-1 rounded -mx-1 transition-colors">
                          <span className="text-zinc-600 flex-shrink-0 w-16">{log.timestamp}</span>
                          <span className={`font-semibold flex-shrink-0 w-10 uppercase ${
                            log.level === 'info' ? 'text-indigo-400' : 
                            log.level === 'warn' ? 'text-amber-400' : 
                            log.level === 'error' ? 'text-red-400' : 
                            'text-emerald-400'
                          }`}>
                            [{log.level}]
                          </span>
                          <span className={`${
                            log.level === 'error' ? 'text-red-300' : 
                            log.level === 'warn' ? 'text-amber-200' : 
                            log.level === 'success' ? 'text-emerald-300 font-medium' :
                            'text-zinc-300'
                          } break-all`}>
                            {log.message}
                          </span>
                        </div>
                      ))}
                      {runningAgents[selectedAgent.id] && (
                        <div className="flex gap-3 px-1 py-1">
                          <span className="text-zinc-600 flex-shrink-0 w-16">--:--:--</span>
                          <span className="text-indigo-400 font-semibold flex-shrink-0 w-10 uppercase animate-pulse">[SYS]</span>
                          <span className="text-zinc-400 flex items-center gap-2">
                            <span className="w-1.5 h-1.5 bg-indigo-500 rounded-full animate-ping"></span>
                            Waiting for output...
                          </span>
                        </div>
                      )}
                      <div ref={logEndRef} className="h-4" />
                    </div>
                  )}
                </div>
              </div>
            </div>
          </>
        )}
      </div>

    </div>
  );
}
