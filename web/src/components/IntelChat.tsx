"use client";

import React, { useState, useRef, useEffect } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Bot, Send, User, X, Maximize2, Minimize2 } from 'lucide-react';

interface Message {
  role: 'user' | 'assistant';
  content: string;
}

export default function IntelChat() {
  const [isOpen, setIsOpen] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);
  const [messages, setMessages] = useState<Message[]>([
    { role: 'assistant', content: "SYSTEM ONLINE. I am the PHANTOM_EYE Neural Agent. How can I assist with your threat hunting today?" }
  ]);
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, isTyping]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;

    const userMessage: Message = { role: 'user', content: input };
    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setIsTyping(true);

    try {
      const history = messages.slice(-5).map(m => ({ role: m.role, content: m.content }));
      
      const API_BASE = process.env.NEXT_PUBLIC_API_BASE || 'http://localhost:8000';
      const response = await fetch(`${API_BASE}/threats/ask`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: userMessage.content, history })
      });
      
      const data = await response.json();
      
      setMessages(prev => [...prev, { role: 'assistant', content: data.answer || "No response received." }]);
    } catch (error) {
      setMessages(prev => [...prev, { role: 'assistant', content: "UPLINK ERROR: Failed to reach Sonar Agent API." }]);
    } finally {
      setIsTyping(false);
    }
  };

  if (!isOpen) {
    return (
      <button 
        onClick={() => setIsOpen(true)}
        className="fixed bottom-6 right-6 z-50 bg-tactical-red text-white p-4 rounded-full shadow-[0_0_20px_rgba(255,0,0,0.5)] hover:scale-110 transition-transform flex items-center justify-center group"
      >
        <Bot className="w-8 h-8" />
        <span className="absolute -top-10 right-0 bg-black/80 px-3 py-1 text-[10px] font-black uppercase tracking-widest border border-white/10 opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap">
          Ask the Intel Agent
        </span>
      </button>
    );
  }

  return (
    <div className={`fixed bottom-0 right-6 z-50 transition-all duration-300 ease-in-out ${isExpanded ? 'w-[800px] h-[80vh]' : 'w-[450px] h-[600px]'} flex flex-col tactical-border bg-[#050505]/95 backdrop-blur-3xl shadow-[0_0_50px_rgba(0,0,0,0.8)]`}>
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-white/10 bg-tactical-red/5">
        <div className="flex items-center gap-3">
          <div className="relative">
            <Bot className="w-6 h-6 text-tactical-red" />
            <div className="absolute top-0 -right-1 w-2 h-2 bg-tactical-red rounded-full animate-ping" />
          </div>
          <div>
            <h3 className="text-[12px] font-black italic tracking-widest uppercase text-white">Neural Intel Agent</h3>
            <p className="text-[9px] font-bold text-cyan-400 tracking-[0.2em] uppercase">Powered by Perplexity Sonar</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => setIsExpanded(!isExpanded)} className="p-1 hover:bg-white/10 text-white/50 hover:text-white transition-colors">
            {isExpanded ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
          </button>
          <button onClick={() => setIsOpen(false)} className="p-1 hover:bg-tactical-red/20 text-white/50 hover:text-tactical-red transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>
      </div>

      {/* Chat Area */}
      <div className="flex-1 overflow-y-auto p-4 space-y-6 scrollbar-custom min-h-0 relative">
        {messages.map((msg, idx) => (
          <div key={idx} className={`flex gap-3 max-w-[90%] ${msg.role === 'user' ? 'ml-auto flex-row-reverse' : ''}`}>
            <div className={`w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 ${msg.role === 'assistant' ? 'bg-tactical-red/20 border border-tactical-red/50' : 'bg-cyan-400/20 border border-cyan-400/50'}`}>
              {msg.role === 'assistant' ? <Bot className="w-4 h-4 text-tactical-red" /> : <User className="w-4 h-4 text-cyan-400" />}
            </div>
            <div className={`flex flex-col gap-1 ${msg.role === 'user' ? 'items-end' : 'items-start'}`}>
              <span className="text-[9px] font-black tracking-widest text-white/30 uppercase italic">
                {msg.role === 'assistant' ? 'PHANTOM_EYE_AGENT' : 'ANALYST_01'}
              </span>
              <div className={`px-4 py-3 text-[12px] font-medium leading-relaxed shadow-lg ${
                msg.role === 'user' 
                  ? 'bg-gradient-to-br from-cyan-900/40 to-black border border-cyan-400/30 text-white' 
                  : 'bg-black border border-white/10 text-white/80 prose prose-invert prose-sm prose-p:leading-relaxed prose-pre:bg-white/5 prose-pre:border prose-pre:border-white/10'
              }`}>
                {msg.role === 'assistant' ? (
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>
                    {msg.content}
                  </ReactMarkdown>
                ) : (
                  msg.content
                )}
              </div>
            </div>
          </div>
        ))}
        {isTyping && (
          <div className="flex gap-3 max-w-[90%]">
            <div className="w-8 h-8 rounded-full bg-tactical-red/20 border border-tactical-red/50 flex items-center justify-center flex-shrink-0">
              <Bot className="w-4 h-4 text-tactical-red animate-pulse" />
            </div>
            <div className="px-4 py-4 bg-black border border-white/10 flex items-center gap-1">
              <div className="w-1.5 h-1.5 bg-tactical-red rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
              <div className="w-1.5 h-1.5 bg-tactical-red rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
              <div className="w-1.5 h-1.5 bg-tactical-red rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input Area */}
      <div className="p-4 border-t border-white/10 bg-black/50">
        <form onSubmit={handleSubmit} className="flex gap-2">
          <input
            type="text"
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder="Query Live OSINT or Ask for Mitigation Context..."
            className="flex-1 bg-white/5 border border-white/10 px-4 py-3 text-[12px] font-bold text-white placeholder:text-white/20 focus:outline-none focus:border-cyan-400 transition-colors"
          />
          <button 
            type="submit" 
            disabled={!input.trim() || isTyping}
            className="bg-tactical-red p-3 flex items-center justify-center text-white hover:bg-tactical-red/80 disabled:opacity-50 transition-colors"
          >
            <Send className="w-5 h-5 pointer-events-none" />
          </button>
        </form>
      </div>
    </div>
  );
}
