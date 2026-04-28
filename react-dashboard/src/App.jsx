import { useEffect, useMemo, useState } from "react";

const API_BASE = "http://localhost:8000";
const EMPTY_STATE = { incidents: [], messages: [], blocked: [], findings: [] };

function severityTone(severity) {
  switch ((severity || "").toUpperCase()) {
    case "CRITICAL":
      return "text-signal-red border-signal-red/40";
    case "HIGH":
      return "text-signal-amber border-signal-amber/40";
    default:
      return "text-signal-cyan border-signal-cyan/40";
  }
}

export default function App() {
  const [state, setState] = useState(EMPTY_STATE);
  const [filters, setFilters] = useState({
    incidentStatus: "all",
    agentType: "all",
    severity: "all",
    blockState: "all"
  });
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);

  useEffect(() => {
    let active = true;

    async function loadState() {
      try {
        const response = await fetch(`${API_BASE}/state`);
        const payload = await response.json();
        if (active) {
          setState(payload);
          if (!selectedIncidentId && payload.incidents.length > 0) {
            setSelectedIncidentId(payload.incidents[0].incident_id);
          }
        }
      } catch (error) {
        console.error("Failed to load ASOC state", error);
      }
    }

    loadState();
    const interval = setInterval(loadState, 5000);

    const socket = new WebSocket("ws://localhost:8000/ws/agent-stream");
    socket.onmessage = (event) => {
      const payload = JSON.parse(event.data);
      setState((current) => ({
        ...current,
        messages: [payload, ...current.messages].slice(0, 100)
      }));
    };

    return () => {
      active = false;
      clearInterval(interval);
      socket.close();
    };
  }, [selectedIncidentId]);

  const filteredMessages = useMemo(() => {
    return state.messages.filter((message) => {
      if (filters.agentType !== "all" && message.agent !== filters.agentType) {
        return false;
      }
      return true;
    });
  }, [filters.agentType, state.messages]);

  const filteredIncidents = useMemo(() => {
    return state.incidents.filter((incident) => {
      if (filters.incidentStatus !== "all" && incident.status !== filters.incidentStatus) {
        return false;
      }
      if (filters.blockState === "active" && !incident.enforcement) {
        return false;
      }
      if (filters.blockState === "unblocked" && incident.enforcement) {
        return false;
      }
      return true;
    });
  }, [filters.blockState, filters.incidentStatus, state.incidents]);

  const filteredFindings = useMemo(() => {
    return state.findings.filter((finding) => {
      if (filters.severity !== "all" && finding.severity !== filters.severity) {
        return false;
      }
      return true;
    });
  }, [filters.severity, state.findings]);

  const selectedIncident = filteredIncidents.find((incident) => incident.incident_id === selectedIncidentId) ?? filteredIncidents[0] ?? null;

  return (
    <div className="min-h-screen bg-[radial-gradient(circle_at_top,_rgba(94,242,255,0.13),_transparent_42%),linear-gradient(180deg,_#08121d_0%,_#07111b_65%,_#04080c_100%)] text-slate-100">
      <div className="mx-auto flex min-h-screen max-w-[1600px] flex-col gap-6 px-4 py-6 lg:px-8">
        <header className="flex flex-col gap-3 rounded-3xl border border-white/10 bg-white/5 p-6 shadow-glow backdrop-blur">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <p className="font-mono text-xs uppercase tracking-[0.4em] text-signal-cyan">Zero-Trust Autonomous SOC</p>
              <h1 className="font-display text-4xl font-bold tracking-tight">ASOC Command Center</h1>
            </div>
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <StatCard label="Incidents" value={state.incidents.length} tone="cyan" />
              <StatCard label="Blocked IPs" value={state.blocked.length} tone="red" />
              <StatCard label="Findings" value={state.findings.length} tone="amber" />
              <StatCard label="Messages" value={state.messages.length} tone="green" />
            </div>
          </div>
          <div className="grid gap-3 md:grid-cols-4">
            <Filter label="Incident" value={filters.incidentStatus} onChange={(value) => setFilters((old) => ({ ...old, incidentStatus: value }))} options={["all", "open", "blocked", "monitoring", "resolved"]} />
            <Filter label="Agent" value={filters.agentType} onChange={(value) => setFilters((old) => ({ ...old, agentType: value }))} options={["all", "supervisor", "traffic-monitor", "incident-responder", "vulnerability-hunter", "auditor"]} />
            <Filter label="Severity" value={filters.severity} onChange={(value) => setFilters((old) => ({ ...old, severity: value }))} options={["all", "CRITICAL", "HIGH"]} />
            <Filter label="Blocks" value={filters.blockState} onChange={(value) => setFilters((old) => ({ ...old, blockState: value }))} options={["all", "active", "unblocked"]} />
          </div>
        </header>

        <div className="grid flex-1 gap-6 xl:grid-cols-[1.2fr_0.8fr]">
          <section className="flex min-h-[650px] flex-col rounded-3xl border border-signal-cyan/20 bg-ink-900/90 p-5 shadow-glow">
            <div className="mb-4 flex items-center justify-between">
              <div>
                <h2 className="font-display text-2xl font-semibold">Live Agent Terminal</h2>
                <p className="font-mono text-xs text-slate-400">Supervisor and specialists streaming decisions in real time.</p>
              </div>
              <div className="rounded-full border border-signal-green/30 bg-signal-green/10 px-3 py-1 font-mono text-xs text-signal-green animate-pulseLine">
                STREAM ACTIVE
              </div>
            </div>
            <div className="flex-1 overflow-hidden rounded-2xl border border-white/10 bg-[#02070c]/90">
              <div className="flex items-center gap-2 border-b border-white/10 px-4 py-3">
                <span className="h-3 w-3 rounded-full bg-signal-red"></span>
                <span className="h-3 w-3 rounded-full bg-signal-amber"></span>
                <span className="h-3 w-3 rounded-full bg-signal-green"></span>
              </div>
              <div className="max-h-[720px] space-y-3 overflow-y-auto px-4 py-4 font-mono text-sm">
                {filteredMessages.map((message, index) => (
                  <div key={`${message.created_at}-${index}`} className="animate-rise rounded-xl border border-white/5 bg-white/[0.03] p-3">
                    <div className="mb-1 flex items-center justify-between gap-4 text-xs uppercase tracking-[0.2em]">
                      <span className="text-signal-cyan">{message.agent}</span>
                      <span className="text-slate-500">{new Date(message.created_at).toLocaleTimeString()}</span>
                    </div>
                    <div className="text-slate-200">{message.content}</div>
                    {message.incident_id && <div className="mt-2 text-[11px] text-slate-500">Incident {message.incident_id}</div>}
                  </div>
                ))}
                {filteredMessages.length === 0 && <EmptyPanel copy="No agent chatter yet. Trigger a traffic event or vulnerability scan to populate the stream." />}
              </div>
            </div>
          </section>

          <section className="grid gap-6">
            <div className="rounded-3xl border border-white/10 bg-white/5 p-5 backdrop-blur">
              <h2 className="font-display text-2xl font-semibold">System Health</h2>
              <div className="mt-4 grid gap-3 sm:grid-cols-2">
                <HealthRow label="Threat posture" value={state.blocked.length > 0 ? "Active containment" : "Monitoring"} tone={state.blocked.length > 0 ? "text-signal-red" : "text-signal-green"} />
                <HealthRow label="Auto-block mode" value="High confidence only" tone="text-signal-cyan" />
                <HealthRow label="Auditor" value="Structured reasoning stored" tone="text-signal-green" />
                <HealthRow label="Retrieval" value="Fingerprint enrichment enabled" tone="text-signal-amber" />
              </div>
            </div>

            <div className="rounded-3xl border border-white/10 bg-white/5 p-5 backdrop-blur">
              <h2 className="font-display text-2xl font-semibold">Blocked IPs</h2>
              <div className="mt-4 space-y-3">
                {state.blocked.map((block) => (
                  <div key={block.action_id} className="rounded-2xl border border-signal-red/20 bg-signal-red/5 p-3 font-mono text-sm">
                    <div className="flex items-center justify-between gap-4">
                      <span className="text-signal-red">{block.source_ip}</span>
                      <span className="text-slate-400">{block.status}</span>
                    </div>
                    <div className="mt-2 text-slate-300">{block.reason}</div>
                  </div>
                ))}
                {state.blocked.length === 0 && <EmptyPanel copy="No active firewall blocks right now." />}
              </div>
            </div>

            <div className="grid gap-6 lg:grid-cols-2">
              <div className="rounded-3xl border border-white/10 bg-white/5 p-5 backdrop-blur">
                <h2 className="font-display text-2xl font-semibold">Incidents</h2>
                <div className="mt-4 space-y-3">
                  {filteredIncidents.map((incident) => (
                    <button
                      key={incident.incident_id}
                      type="button"
                      onClick={() => setSelectedIncidentId(incident.incident_id)}
                      className={`w-full rounded-2xl border p-3 text-left transition ${selectedIncident?.incident_id === incident.incident_id ? "border-signal-cyan bg-signal-cyan/10" : "border-white/10 bg-black/10 hover:border-signal-cyan/30"}`}
                    >
                      <div className="flex items-center justify-between gap-3">
                        <span className="font-mono text-xs uppercase tracking-[0.2em] text-slate-400">{incident.status}</span>
                        <span className="font-mono text-xs text-slate-500">{incident.source_ip}</span>
                      </div>
                      <p className="mt-2 text-sm text-slate-200">{incident.summary}</p>
                    </button>
                  ))}
                  {filteredIncidents.length === 0 && <EmptyPanel copy="No incidents match the active filters." />}
                </div>
              </div>

              <div className="rounded-3xl border border-white/10 bg-white/5 p-5 backdrop-blur">
                <h2 className="font-display text-2xl font-semibold">Incident Drill-Down</h2>
                {selectedIncident ? (
                  <div className="mt-4 space-y-4">
                    <DetailRow label="Source IP" value={selectedIncident.source_ip} />
                    <DetailRow label="Classification" value={`${selectedIncident.assessment.label} (${selectedIncident.assessment.confidence})`} />
                    <DetailRow label="Patterns" value={selectedIncident.assessment.matched_patterns.join(", ") || "none"} />
                    <DetailRow label="Response" value={selectedIncident.enforcement?.status || "no block applied"} />
                    <div className="rounded-2xl border border-white/10 bg-black/10 p-3">
                      <p className="mb-2 font-mono text-xs uppercase tracking-[0.2em] text-slate-400">Audit Trail</p>
                      <div className="space-y-2">
                        {selectedIncident.audit_trail.map((entry) => (
                          <div key={entry.event_id} className="rounded-xl border border-white/5 bg-white/[0.03] p-2">
                            <div className="font-mono text-[11px] uppercase tracking-[0.2em] text-signal-cyan">{entry.actor}</div>
                            <div className="mt-1 text-sm text-slate-300">{entry.summary}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="mt-4"><EmptyPanel copy="Select an incident to inspect the raw assessment, response, and audit trail." /></div>
                )}
              </div>
            </div>

            <div className="rounded-3xl border border-white/10 bg-white/5 p-5 backdrop-blur">
              <h2 className="font-display text-2xl font-semibold">Recent Vulnerabilities</h2>
              <div className="mt-4 grid gap-3">
                {filteredFindings.map((finding) => (
                  <div key={finding.finding_id} className={`rounded-2xl border bg-black/10 p-3 ${severityTone(finding.severity)}`}>
                    <div className="flex items-center justify-between gap-3">
                      <span className="font-mono text-xs uppercase tracking-[0.2em]">{finding.severity}</span>
                      <span className="font-mono text-xs text-slate-500">{finding.file_path}</span>
                    </div>
                    <p className="mt-2 text-sm text-slate-200">{finding.explanation}</p>
                  </div>
                ))}
                {filteredFindings.length === 0 && <EmptyPanel copy="No vulnerability findings available yet. Run a repository scan from the orchestrator." />}
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value, tone }) {
  const toneMap = {
    cyan: "text-signal-cyan border-signal-cyan/30 bg-signal-cyan/10",
    red: "text-signal-red border-signal-red/30 bg-signal-red/10",
    amber: "text-signal-amber border-signal-amber/30 bg-signal-amber/10",
    green: "text-signal-green border-signal-green/30 bg-signal-green/10"
  };
  return (
    <div className={`rounded-2xl border px-4 py-3 ${toneMap[tone]}`}>
      <div className="font-mono text-[11px] uppercase tracking-[0.22em]">{label}</div>
      <div className="mt-1 font-display text-2xl font-bold">{value}</div>
    </div>
  );
}

function Filter({ label, value, onChange, options }) {
  return (
    <label className="grid gap-2 font-mono text-xs uppercase tracking-[0.2em] text-slate-400">
      {label}
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="rounded-2xl border border-white/10 bg-black/20 px-3 py-2 text-sm text-slate-100 outline-none ring-0"
      >
        {options.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
    </label>
  );
}

function HealthRow({ label, value, tone }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-black/10 p-3">
      <div className="font-mono text-[11px] uppercase tracking-[0.2em] text-slate-500">{label}</div>
      <div className={`mt-1 text-sm ${tone}`}>{value}</div>
    </div>
  );
}

function DetailRow({ label, value }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-black/10 p-3">
      <div className="font-mono text-[11px] uppercase tracking-[0.2em] text-slate-500">{label}</div>
      <div className="mt-1 text-sm text-slate-200">{value}</div>
    </div>
  );
}

function EmptyPanel({ copy }) {
  return (
    <div className="rounded-2xl border border-dashed border-white/10 bg-black/10 p-4 text-sm text-slate-400">
      {copy}
    </div>
  );
}

