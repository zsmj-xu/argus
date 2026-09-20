import React, { useState } from 'react';
import {
  ChevronDown,
  ChevronRight,
  Info,
  AlertTriangle,
  AlertCircle,
  Archive,
  Terminal,
} from 'lucide-react';
import { ScanEvent } from '../../types/api';
import { formatDate } from '../../lib/utils';

interface EventStreamProps {
  events: ScanEvent[];
  historyTruncated?: boolean;
  expiredEventCount?: number;
  isPolling?: boolean;
}

export const EventStream: React.FC<EventStreamProps> = ({
  events,
  historyTruncated,
  expiredEventCount = 0,
  isPolling,
}) => {
  const [levelFilter, setLevelFilter] = useState<'all' | 'info' | 'warn' | 'error'>('all');
  const [expandedEventIds, setExpandedEventIds] = useState<Set<number>>(new Set());

  const toggleExpand = (id: number) => {
    setExpandedEventIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const filteredEvents = events.filter((e) => {
    if (levelFilter === 'all') return true;
    const lvl = (e.level || 'info').toLowerCase();
    if (levelFilter === 'warn') return lvl.includes('warn');
    if (levelFilter === 'error') return lvl.includes('error');
    return lvl.includes('info');
  });

  return (
    <div className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-5 space-y-4">
      {/* Header & Filter */}
      <div className="flex items-center justify-between border-b border-zinc-800/80 pb-3 flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-sky-400" />
          <span className="font-semibold text-xs text-zinc-200 uppercase tracking-wider">
            增量运行事件时间轴 (Incremental Events)
          </span>
          <span className="text-xs font-mono text-zinc-500">({events.length} 条)</span>
          {isPolling && (
            <span className="inline-flex items-center gap-1 text-[10px] text-sky-400 font-mono px-2 py-0.5 rounded bg-sky-950/60 border border-sky-800/40 animate-pulse">
              实时监听中
            </span>
          )}
        </div>

        {/* Filter buttons */}
        <div className="flex items-center gap-1 bg-zinc-950 p-1 rounded-lg border border-zinc-800 text-xs">
          {(['all', 'info', 'warn', 'error'] as const).map((lvl) => (
            <button
              key={lvl}
              onClick={() => setLevelFilter(lvl)}
              className={`px-2.5 py-1 rounded capitalize transition-colors ${
                levelFilter === lvl
                  ? 'bg-zinc-800 text-zinc-100 font-medium'
                  : 'text-zinc-500 hover:text-zinc-300'
              }`}
            >
              {lvl}
            </button>
          ))}
        </div>
      </div>

      {/* History Truncated Alert */}
      {(historyTruncated || expiredEventCount > 0) && (
        <div className="p-3 bg-zinc-950 border border-zinc-800 rounded-lg text-xs text-zinc-400 flex items-center gap-2">
          <Archive className="w-4 h-4 text-zinc-500 shrink-0" />
          <span>
            早期事件归档提示：已有 {expiredEventCount > 0 ? `${expiredEventCount} 条` : ''}
            事件根据保留策略（14天/1万条限制）自动归档，历史记录存在时间断层，属正常现象。
          </span>
        </div>
      )}

      {/* Event Timeline List */}
      {filteredEvents.length === 0 ? (
        <div className="text-center py-10 text-xs text-zinc-500">
          暂无符合过滤条件的事件事实
        </div>
      ) : (
        <div className="space-y-2 max-h-[480px] overflow-y-auto pr-1 font-mono text-xs">
          {filteredEvents.map((event, idx) => {
            const eventKey = event.event_id ?? event.id ?? idx;
            const isExpanded = expandedEventIds.has(eventKey);
            const hasData = event.data && Object.keys(event.data).length > 0;

            let levelColor = 'text-sky-400 bg-sky-950/40 border-sky-800/50';
            let IconComponent = Info;

            const lvl = (event.level || '').toLowerCase();
            if (lvl.includes('warn')) {
              levelColor = 'text-amber-400 bg-amber-950/40 border-amber-800/50';
              IconComponent = AlertTriangle;
            } else if (lvl.includes('error')) {
              levelColor = 'text-rose-400 bg-rose-950/40 border-rose-800/50';
              IconComponent = AlertCircle;
            }

            return (
              <div
                key={eventKey}
                className="bg-zinc-950/80 border border-zinc-800/60 rounded-lg p-2.5 hover:border-zinc-700 transition-colors"
              >
                <div
                  className={`flex items-start justify-between gap-3 ${
                    hasData ? 'cursor-pointer' : ''
                  }`}
                  onClick={() => hasData && toggleExpand(eventKey)}
                >
                  <div className="flex items-start gap-2.5 min-w-0">
                    <span
                      className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] font-semibold uppercase shrink-0 mt-0.5 ${levelColor}`}
                    >
                      <IconComponent className="w-3 h-3" />
                      {event.level || 'info'}
                    </span>

                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-zinc-200 font-semibold">{event.type}</span>
                        {event.stage && (
                          <span className="text-[11px] text-zinc-500">
                            [{event.stage}]
                          </span>
                        )}
                        {event.code && (
                          <span className="text-[10px] text-zinc-400 bg-zinc-900 px-1 rounded">
                            {event.code}
                          </span>
                        )}
                      </div>
                      <p className="text-zinc-400 text-xs mt-0.5 break-all">
                        {event.message}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-[11px] text-zinc-500">
                      {formatDate(event.timestamp || event.created_at)}
                    </span>
                    {hasData && (
                      <div className="text-zinc-500 hover:text-zinc-300">
                        {isExpanded ? (
                          <ChevronDown className="w-4 h-4" />
                        ) : (
                          <ChevronRight className="w-4 h-4" />
                        )}
                      </div>
                    )}
                  </div>
                </div>

                {/* Expanded JSON Data */}
                {isExpanded && hasData && (
                  <div className="mt-2 pt-2 border-t border-zinc-800/80 text-[11px] text-zinc-300 bg-zinc-900/50 p-2 rounded">
                    <pre className="overflow-x-auto whitespace-pre-wrap">
                      {JSON.stringify(event.data, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
