'use client';

import { useState } from 'react';

export default function Home() {
  const [repoUrl, setRepoUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<any>(null);

  const handleScan = async () => {
    setScanning(true);
    try {
      const response = await fetch('http://localhost:8000/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo_url: repoUrl, scan_type: 'quick' })
      });
      const data = await response.json();
      setResult(data);
    } catch (err) {
      alert('Error: Make sure backend is running');
    } finally {
      setScanning(false);
    }
  };

  const loadDemo = async () => {
    setScanning(true);
    const response = await fetch('http://localhost:8000/demo');
    const data = await response.json();
    setResult(data);
    setRepoUrl('https://github.com/demo/project');
    setScanning(false);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 text-white">
      <div className="max-w-4xl mx-auto p-8">
        <h1 className="text-5xl font-bold mb-4 bg-gradient-to-r from-purple-400 to-pink-600 bg-clip-text text-transparent">
          GuardianAI
        </h1>
        <p className="text-xl text-gray-300 mb-8">AI Security Scanner for DevOps Pipelines</p>
        
        <div className="bg-slate-800/50 p-6 rounded-lg mb-6">
          <input
            type="text"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            placeholder="https://github.com/owner/repo"
            className="w-full p-3 bg-slate-900 rounded mb-3 text-white"
          />
          <button
            onClick={handleScan}
            disabled={scanning}
            className="bg-purple-600 px-6 py-3 rounded mr-3 disabled:opacity-50"
          >
            {scanning ? 'Scanning...' : 'Scan Now'}
          </button>
          <button onClick={loadDemo} className="bg-gray-600 px-6 py-3 rounded">
            Try Demo
          </button>
        </div>

        {result && (
          <div className="bg-slate-800/50 p-6 rounded-lg">
            <h2 className="text-2xl font-bold mb-4">Results</h2>
            <div className="grid grid-cols-3 gap-4 mb-6">
              <div className="bg-slate-900 p-4 rounded text-center">
                <div className="text-3xl font-bold text-purple-400">{result.maturity_score}%</div>
                <div className="text-sm text-gray-400">Score</div>
              </div>
              <div className="bg-slate-900 p-4 rounded text-center">
                <div className="text-3xl font-bold text-cyan-400">{result.maturity_level?.split(':')[0]}</div>
                <div className="text-sm text-gray-400">Level</div>
              </div>
              <div className="bg-slate-900 p-4 rounded text-center">
                <div className="text-3xl font-bold text-pink-400">{result.scan_time}s</div>
                <div className="text-sm text-gray-400">Time</div>
              </div>
            </div>
            
            <div className="mb-4">
              <h3 className="font-bold mb-2">🤖 AI Analysis</h3>
              <p className="text-gray-300">{result.ai_summary}</p>
            </div>
            
            <div>
              <h3 className="font-bold mb-2">💡 Recommendations</h3>
              {result.recommendations?.map((rec: string, i: number) => (
                <div key={i} className="bg-slate-900 p-2 rounded mb-2">
                  {i + 1}. {rec}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
