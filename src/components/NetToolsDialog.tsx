import { useEffect, useRef, useState } from 'react'
import { Activity, Globe, Radar, Route, Square, X } from 'lucide-react'
import { safeInvoke, safeListen } from '../lib/tauri'

interface ToolEvent {
  runId: string
  line: string
  done: boolean
}

/* ---------------------------------------------------------------------------
   Basic network troubleshooting: ping, traceroute, port check, DNS.

   Nothing fancy on purpose — these are the four questions asked in the first
   two minutes of any "it's down" call: does it answer, which path, is the
   service listening, does the name even resolve. Ping and traceroute stream
   line-by-line (a 20-hop trace takes real time, and dead air reads as a hang);
   port check and DNS return in one shot.

   These run from THIS machine, not from a session — that is the point. When
   the SSH session cannot connect, this dialog is how you find out why.
--------------------------------------------------------------------------- */
export function NetToolsDialog({
  initialTarget,
  initialPort,
  onClose,
}: {
  initialTarget: string
  initialPort?: number
  onClose: () => void
}) {
  const [target, setTarget] = useState(initialTarget)
  const [port, setPort] = useState(String(initialPort ?? 22))
  const [lines, setLines] = useState<string[]>([])
  const [running, setRunning] = useState<string | null>(null)
  const runIdRef = useRef<string | null>(null)
  const unlistenRef = useRef<(() => void) | null>(null)
  const outRef = useRef<HTMLPreElement>(null)

  // Read through a ref: the parent passes a fresh inline onClose on every
  // render, and keying an effect on it re-ran the cleanup below — cancelling a
  // live traceroute whenever anything else in the app re-rendered.
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onCloseRef.current()
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
  }, [])

  // Unmount only: leaving the dialog cancels a live run — a traceroute nobody
  // is watching is pure wasted probe traffic.
  useEffect(
    () => () => {
      if (runIdRef.current) void safeInvoke('net_tool_cancel', { runId: runIdRef.current })
      unlistenRef.current?.()
    },
    [],
  )

  // Follow output as it arrives.
  useEffect(() => {
    outRef.current?.scrollTo(0, outRef.current.scrollHeight)
  }, [lines])

  const append = (text: string) => setLines((l) => [...l, text])

  const startStream = async (tool: 'ping' | 'traceroute') => {
    if (running) return
    const runId = `${tool}-${Date.now()}`
    runIdRef.current = runId
    setRunning(tool)
    append(`$ ${tool} ${target}`)

    unlistenRef.current = await safeListen<ToolEvent>(`net://${runId}`, (ev) => {
      if (ev.done) {
        setRunning(null)
        runIdRef.current = null
        unlistenRef.current?.()
        unlistenRef.current = null
      } else if (ev.line.trim() !== '') {
        append(ev.line)
      }
    })

    try {
      await safeInvoke('net_tool_start', { runId, tool, target: target.trim() })
    } catch (e) {
      append(`error: ${e instanceof Error ? e.message : e}`)
      setRunning(null)
      runIdRef.current = null
      unlistenRef.current?.()
      unlistenRef.current = null
    }
  }

  const stop = () => {
    if (runIdRef.current) {
      void safeInvoke('net_tool_cancel', { runId: runIdRef.current })
      append('(cancelled)')
      setRunning(null)
      runIdRef.current = null
      // A cancelled run never sends `done`, so drop its listener here.
      unlistenRef.current?.()
      unlistenRef.current = null
    }
  }

  const checkPort = async () => {
    if (running) return
    setRunning('port')
    append(`$ port-check ${target}:${port}`)
    try {
      const result = await safeInvoke<string>('net_port_check', {
        target: target.trim(),
        port: Number(port) || 22,
      })
      append(result ?? '(no result)')
    } catch (e) {
      append(`error: ${e instanceof Error ? e.message : e}`)
    } finally {
      setRunning(null)
    }
  }

  const lookup = async () => {
    if (running) return
    setRunning('dns')
    append(`$ resolve ${target}`)
    try {
      const addrs = await safeInvoke<string[]>('net_dns_lookup', { target: target.trim() })
      ;(addrs ?? []).forEach((a) => append(`  ${a}`))
    } catch (e) {
      append(`error: ${e instanceof Error ? e.message : e}`)
    } finally {
      setRunning(null)
    }
  }

  const toolBtn =
    'flex h-7 items-center gap-1.5 rounded border border-line px-2.5 text-[12px] text-ink-dim transition-colors hover:bg-surface-3 hover:text-ink disabled:opacity-40'

  return (
    <div className="absolute inset-0 z-50 flex justify-center">
      <div className="animate-scrim-in absolute inset-0 bg-surface-0/75 backdrop-blur-[2px]" aria-hidden />

      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="nt-title"
        className="animate-drop-in relative mt-10 flex h-[70vh] w-[40rem] max-w-[94vw] flex-col overflow-hidden rounded-panel border border-line-strong bg-surface-2 shadow-[0_24px_60px_-12px_rgba(0,0,0,0.75)]"
      >
        <header className="flex items-center gap-2 border-b border-line px-4 py-2.5">
          <Activity size={15} className="shrink-0 text-accent" aria-hidden />
          <h2 id="nt-title" className="flex-1 text-[13.5px] font-medium text-ink">
            Network tools
          </h2>
          <button
            type="button"
            aria-label="Close"
            onClick={onClose}
            className="grid h-6 w-6 place-items-center rounded text-ink-faint hover:bg-surface-3 hover:text-ink"
          >
            <X size={14} />
          </button>
        </header>

        <div className="flex flex-wrap items-end gap-2 border-b border-line px-4 py-2.5">
          <label className="block min-w-0 flex-1">
            <span className="mb-1 block text-[10.5px] uppercase tracking-wider text-ink-faint">
              Target
            </span>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="hostname or IP"
              className="h-7 w-full rounded border border-line bg-surface-0 px-2 font-mono text-[12px] text-ink placeholder:text-ink-faint focus:border-accent focus:outline-none"
            />
          </label>
          <label className="block w-20">
            <span className="mb-1 block text-[10.5px] uppercase tracking-wider text-ink-faint">
              Port
            </span>
            <input
              value={port}
              onChange={(e) => setPort(e.target.value.replace(/\D/g, ''))}
              className="h-7 w-full rounded border border-line bg-surface-0 px-2 font-mono text-[12px] text-ink focus:border-accent focus:outline-none"
            />
          </label>
        </div>

        <div className="flex items-center gap-1.5 border-b border-line px-4 py-2">
          <button type="button" disabled={!!running} onClick={() => void startStream('ping')} className={toolBtn}>
            <Radar size={12} aria-hidden /> Ping
          </button>
          <button type="button" disabled={!!running} onClick={() => void startStream('traceroute')} className={toolBtn}>
            <Route size={12} aria-hidden /> Traceroute
          </button>
          <button type="button" disabled={!!running} onClick={() => void checkPort()} className={toolBtn}>
            <Activity size={12} aria-hidden /> Port check
          </button>
          <button type="button" disabled={!!running} onClick={() => void lookup()} className={toolBtn}>
            <Globe size={12} aria-hidden /> DNS
          </button>
          <div className="flex-1" />
          {running && (
            <button
              type="button"
              onClick={stop}
              className="flex h-7 items-center gap-1.5 rounded border border-warn/60 bg-warn/10 px-2.5 text-[12px] text-warn hover:bg-warn/20"
            >
              <Square size={11} aria-hidden /> Stop
            </button>
          )}
          <button
            type="button"
            onClick={() => setLines([])}
            className="h-7 rounded border border-line px-2 text-[11.5px] text-ink-faint hover:bg-surface-3 hover:text-ink"
          >
            Clear
          </button>
        </div>

        <pre
          ref={outRef}
          className="selectable min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-words bg-surface-0 p-3 font-mono text-[12px] leading-relaxed text-ink-dim"
        >
          {lines.length === 0
            ? 'Output appears here. These probes run from this machine — useful precisely when SSH cannot connect.'
            : lines.join('\n')}
        </pre>
      </div>
    </div>
  )
}
