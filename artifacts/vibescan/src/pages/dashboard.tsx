import { useEffect, useRef, useState } from "react";
import { Link, useLocation } from "wouter";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useSeo } from "@/lib/seo";
import { useListScans, useGetCredits, useGetScanStatus, getGetScanStatusQueryKey } from "@workspace/api-client-react";
import {
  Shield, Plus, Clock, CheckCircle2, AlertCircle, RefreshCw, FileText, Loader2, ArrowRight, Info,
  Zap as ZapIcon, Bell, AlertTriangle, Terminal, Copy, Check, Trash2, ChevronDown, ChevronUp, KeyRound,
} from "lucide-react";
import { format } from "date-fns";
import { cn } from "@/lib/utils";
import type { Scan } from "@workspace/api-client-react";
import { listMonitorSubscriptions } from "@/lib/monitor-api";
import { listCiApiKeys, createCiApiKey, revokeCiApiKey, type CiApiKey } from "@/lib/ci-api";
import { useToast } from "@/hooks/use-toast";

const GRADE_COLORS: Record<string, string> = {
  A: "text-emerald-400 bg-emerald-400/10 border-emerald-400/30",
  B: "text-green-400 bg-green-400/10 border-green-400/30",
  C: "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
  D: "text-orange-400 bg-orange-400/10 border-orange-400/30",
  F: "text-red-400 bg-red-400/10 border-red-400/30",
};

function GradeBadge({ grade }: { grade: string | null | undefined }) {
  const key = grade ?? "";
  const colors = GRADE_COLORS[key] ?? "text-muted-foreground bg-secondary border-white/10";
  return (
    <div className={cn("w-9 h-9 rounded-lg border flex items-center justify-center font-bold text-lg", colors)}>
      {grade ?? "?"}
    </div>
  );
}

function ScanRow({ initialScan, highlight }: { initialScan: Scan; highlight?: boolean }) {
  const rowRef = useRef<HTMLTableRowElement>(null);
  const [, setLocation] = useLocation();
  const wasPolling = useRef(['pending', 'paid', 'queued', 'scanning', 'analyzing'].includes(initialScan.status));
  const isPolling = ['pending', 'paid', 'queued', 'scanning', 'analyzing'].includes(initialScan.status);

  const { data: statusData } = useGetScanStatus(initialScan.id, {
    query: {
      queryKey: getGetScanStatusQueryKey(initialScan.id),
      refetchInterval: isPolling ? 3000 : false,
    },
  });

  const scan = statusData ?? initialScan;

  // Auto-redirect to report when scan transitions from in-progress to complete
  useEffect(() => {
    if (
      wasPolling.current &&
      scan.status === "complete" &&
      "reportId" in scan &&
      scan.reportId
    ) {
      wasPolling.current = false;
      setLocation(`/report/${scan.reportId}`);
    }
    if (!["pending", "paid", "queued", "scanning", "analyzing"].includes(scan.status)) {
      wasPolling.current = false;
    }
  }, [scan.status, scan, setLocation]);

  // Scroll into view when highlighted (new scan from checkout)
  useEffect(() => {
    if (highlight && rowRef.current) {
      rowRef.current.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }, [highlight]);

  const getStatusDisplay = (status: string, progress?: number) => {
    switch (status) {
      case 'complete':
        return (
          <div className="flex items-center gap-1.5 text-emerald-400">
            <CheckCircle2 className="w-4 h-4" /> Complete
          </div>
        );
      case 'failed':
        return (
          <div className="flex items-center gap-1.5 text-red-400">
            <AlertCircle className="w-4 h-4" /> Failed
          </div>
        );
      case 'pending':
      case 'paid':
      case 'queued':
        return (
          <div className="flex items-center gap-1.5 text-muted-foreground">
            <Clock className="w-4 h-4" /> Queued
          </div>
        );
      default:
        return (
          <div className="flex items-center gap-2 text-primary">
            <Loader2 className="w-4 h-4 animate-spin" />
            <div className="flex flex-col gap-1 w-24">
              <span className="text-xs capitalize">{status}…</span>
              <div className="h-1 w-full bg-secondary rounded-full overflow-hidden">
                <div
                  className="h-full bg-primary transition-all duration-500"
                  style={{ width: `${progress ?? 0}%` }}
                />
              </div>
            </div>
          </div>
        );
    }
  };

  const errorMsg = 'error' in scan ? scan.error : null;

  return (
    <tr
      ref={rowRef}
      className={cn(
        "border-b border-white/5 hover:bg-white/[0.02] transition-colors group",
        highlight && "ring-1 ring-primary/30 bg-primary/5",
      )}
    >
      <td className="p-4 py-5">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-secondary flex items-center justify-center border border-white/5 shrink-0">
            <GlobeIcon className="w-5 h-5 text-muted-foreground" />
          </div>
          <div className="min-w-0">
            <div className="font-medium text-foreground truncate max-w-[180px] sm:max-w-[280px] lg:max-w-[360px]">
              {scan.targetUrl}
            </div>
            <div className="text-xs text-muted-foreground mt-1">
              {format(new Date(scan.createdAt), "MMM d, yyyy h:mm a")}
            </div>
          </div>
        </div>
      </td>

      <td className="p-4 hidden sm:table-cell">
        <span className="px-2.5 py-1 rounded-md text-xs font-medium bg-secondary border border-white/5 uppercase tracking-wider">
          {scan.tier.replace('_', ' ')}
        </span>
      </td>

      <td className="p-4">
        {getStatusDisplay(scan.status, 'progress' in scan ? scan.progress : undefined)}
      </td>

      <td className="p-4 hidden md:table-cell">
        {(() => {
          const grade = 'grade' in scan ? (scan as { grade?: string | null }).grade : null;
          if (scan.status === 'complete' && grade) return <GradeBadge grade={grade} />;
          if (scan.status === 'complete') return <Shield className="w-5 h-5 text-emerald-400" />;
          if (scan.status === 'failed') return <AlertCircle className="w-5 h-5 text-red-400/50" />;
          return <span className="text-muted-foreground">—</span>;
        })()}
      </td>

      <td className="p-4 text-right">
        {scan.status === 'complete' && 'reportId' in scan && scan.reportId ? (
          <Link
            href={`/report/${scan.reportId}`}
            className="inline-flex items-center gap-2 px-4 py-2 bg-secondary hover:bg-white/10 text-foreground text-sm font-medium rounded-lg transition-colors border border-white/5"
          >
            <FileText className="w-4 h-4" /> View Report
          </Link>
        ) : scan.status === 'failed' ? (
          <div className="flex items-center justify-end gap-2">
            {errorMsg && (
              <div className="relative group/tooltip">
                <button className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors">
                  <Info className="w-4 h-4" /> Details
                </button>
                <div className="absolute right-0 bottom-full mb-2 w-64 p-3 bg-card border border-white/10 rounded-xl shadow-xl text-xs text-muted-foreground opacity-0 group-hover/tooltip:opacity-100 pointer-events-none transition-opacity z-50 text-left">
                  <p className="font-semibold text-foreground mb-1">Error Details</p>
                  <p>{errorMsg}</p>
                </div>
              </div>
            )}
            <Link
              href="/scan"
              className="text-xs text-primary hover:underline underline-offset-4"
            >
              Retry
            </Link>
          </div>
        ) : (
          <span className="text-xs text-muted-foreground">Processing…</span>
        )}
      </td>
    </tr>
  );
}

function GlobeIcon(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="24" height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      <circle cx="12" cy="12" r="10" />
      <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20" />
      <path d="M2 12h20" />
    </svg>
  );
}

function ciActionSnippet(origin: string): string {
  return `- name: Run VibeScan security gate
  run: |
    curl -sf -X POST "${origin}/api/ci/scan" \\
      -H "Authorization: Bearer \${{ secrets.VIBESCAN_CI_KEY }}" \\
      -H "Content-Type: application/json" \\
      -d '{"targetUrl":"https://your-preview-url.com","failOn":"high"}' \\
      -o vibescan-result.json
    cat vibescan-result.json
    passed=$(jq -r '.passed' vibescan-result.json)
    if [ "$passed" != "true" ]; then
      echo "::error::VibeScan found blocking issues — $(jq -r '.reportUrl' vibescan-result.json)"
      exit 1
    fi`;
}

function CiIntegrationSection() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [showSetup, setShowSetup] = useState(false);
  const [creating, setCreating] = useState(false);
  const [revealedToken, setRevealedToken] = useState<string | null>(null);
  const [copied, setCopied] = useState<"token" | "snippet" | null>(null);

  const { data: keys, isLoading } = useQuery({
    queryKey: ["ci-api-keys"],
    queryFn: listCiApiKeys,
  });

  async function copy(text: string, which: "token" | "snippet") {
    await navigator.clipboard.writeText(text);
    setCopied(which);
    setTimeout(() => setCopied((c) => (c === which ? null : c)), 2000);
  }

  async function handleCreate() {
    setCreating(true);
    try {
      const created = await createCiApiKey();
      setRevealedToken(created.token);
      setShowSetup(true);
      queryClient.invalidateQueries({ queryKey: ["ci-api-keys"] });
    } catch {
      toast({ title: "Failed to create key", description: "Please try again in a moment.", variant: "destructive" });
    } finally {
      setCreating(false);
    }
  }

  async function handleRevoke(key: CiApiKey) {
    if (!confirm(`Revoke "${key.name}"? Any CI pipeline using it will stop working immediately.`)) return;
    try {
      await revokeCiApiKey(key.id);
      queryClient.invalidateQueries({ queryKey: ["ci-api-keys"] });
    } catch {
      toast({ title: "Failed to revoke key", description: "Please try again in a moment.", variant: "destructive" });
    }
  }

  const origin = typeof window !== "undefined" ? window.location.origin : "https://seclayer.io";

  return (
    <div className="glass-panel rounded-2xl p-6 mb-10">
      <div className="flex items-start justify-between gap-4 flex-wrap mb-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center shrink-0">
            <Terminal className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h2 className="font-bold text-lg">CI/CD Integration</h2>
            <p className="text-sm text-muted-foreground">Gate your pull requests on a VibeScan grade — no dashboard required.</p>
          </div>
        </div>
        <button
          onClick={handleCreate}
          disabled={creating}
          className="flex items-center gap-1.5 px-4 py-2 bg-primary/10 border border-primary/20 hover:bg-primary/20 text-primary text-sm font-semibold rounded-lg transition-colors disabled:opacity-50"
        >
          {creating ? <Loader2 className="w-4 h-4 animate-spin" /> : <KeyRound className="w-4 h-4" />}
          New CI Key
        </button>
      </div>

      {revealedToken && (
        <div className="mb-4 p-4 rounded-xl bg-amber-400/10 border border-amber-400/25">
          <p className="text-xs font-semibold text-amber-400 mb-2">
            Copy this key now — it won't be shown again.
          </p>
          <div className="flex items-center gap-2">
            <code className="flex-1 min-w-0 truncate text-xs bg-background/60 rounded-lg px-3 py-2 font-mono">
              {revealedToken}
            </code>
            <button
              onClick={() => copy(revealedToken, "token")}
              className="shrink-0 flex items-center gap-1.5 px-3 py-2 bg-secondary hover:bg-white/10 rounded-lg text-xs font-medium transition-colors"
            >
              {copied === "token" ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copied === "token" ? "Copied" : "Copy"}
            </button>
          </div>
          <button
            onClick={() => setRevealedToken(null)}
            className="text-xs text-muted-foreground hover:text-foreground mt-2 underline underline-offset-4"
          >
            I've saved it — dismiss
          </button>
        </div>
      )}

      {isLoading ? (
        <div className="flex items-center gap-2 text-sm text-muted-foreground py-2">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading keys…
        </div>
      ) : keys && keys.length > 0 ? (
        <div className="space-y-2 mb-4">
          {keys.map((key) => (
            <div key={key.id} className="flex items-center gap-3 px-4 py-3 rounded-xl bg-secondary/40 border border-white/5">
              <KeyRound className="w-4 h-4 text-muted-foreground shrink-0" />
              <div className="min-w-0 flex-1">
                <div className="text-sm font-medium truncate">{key.name}</div>
                <div className="text-xs text-muted-foreground font-mono">
                  {key.tokenPrefix}… · {key.lastUsedAt ? `last used ${format(new Date(key.lastUsedAt), "MMM d, yyyy")}` : "never used"}
                </div>
              </div>
              <button
                onClick={() => handleRevoke(key)}
                className="shrink-0 p-2 rounded-lg hover:bg-red-400/10 text-muted-foreground hover:text-red-400 transition-colors"
                title="Revoke key"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          ))}
        </div>
      ) : (
        <p className="text-sm text-muted-foreground mb-4">No CI keys yet — create one to start gating pull requests on a scan grade.</p>
      )}

      <button
        onClick={() => setShowSetup((s) => !s)}
        className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
      >
        {showSetup ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        {showSetup ? "Hide" : "Show"} setup instructions
      </button>

      {showSetup && (
        <div className="mt-4 space-y-3">
          <p className="text-xs text-muted-foreground">
            Add your key as a repo secret named <code className="px-1 py-0.5 bg-secondary rounded">VIBESCAN_CI_KEY</code>, then add this step to any GitHub Actions workflow (works the same in any CI system via plain <code className="px-1 py-0.5 bg-secondary rounded">curl</code>):
          </p>
          <div className="relative">
            <pre className="text-xs bg-background/60 border border-white/10 rounded-xl p-4 overflow-x-auto font-mono leading-relaxed">
              {ciActionSnippet(origin)}
            </pre>
            <button
              onClick={() => copy(ciActionSnippet(origin), "snippet")}
              className="absolute top-3 right-3 flex items-center gap-1.5 px-2.5 py-1.5 bg-secondary hover:bg-white/10 rounded-lg text-xs font-medium transition-colors"
            >
              {copied === "snippet" ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copied === "snippet" ? "Copied" : "Copy"}
            </button>
          </div>
          <p className="text-xs text-muted-foreground">
            <code className="px-1 py-0.5 bg-secondary rounded">failOn</code> can be <code className="px-1 py-0.5 bg-secondary rounded">critical</code>, <code className="px-1 py-0.5 bg-secondary rounded">high</code>, <code className="px-1 py-0.5 bg-secondary rounded">medium</code>, or <code className="px-1 py-0.5 bg-secondary rounded">never</code> (report only, never fail the build).
          </p>
        </div>
      )}
    </div>
  );
}

export default function DashboardPage() {
  useSeo({ title: "Dashboard — Seclayer", noindex: true });
  const params = new URLSearchParams(
    typeof window !== "undefined" ? window.location.search : "",
  );
  const highlightScanId = params.get("scan");
  const creditsPurchased = params.get("credits") === "purchased";

  const { data: scans, isLoading: loadingScans } = useListScans();
  const { data: credits, isLoading: loadingCredits } = useGetCredits();
  const { data: monitors } = useQuery({
    queryKey: ["monitor-subscriptions"],
    queryFn: listMonitorSubscriptions,
  });

  if (loadingScans || loadingCredits) {
    return (
      <div className="flex-1 flex items-center justify-center min-h-[60vh]">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  const completedCount = scans?.filter((s) => s.status === 'complete').length ?? 0;
  const activeMonitors = monitors?.filter((m) => m.status === 'active') ?? [];
  const pendingCveAlerts = activeMonitors.reduce((sum, m) => sum + m.alertCount, 0);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
          <p className="text-muted-foreground mt-1">Manage your security scans and reports.</p>
        </div>
        <Link
          href="/scan"
          className="px-5 py-2.5 bg-primary text-primary-foreground text-sm font-semibold rounded-lg shadow-[0_0_15px_rgba(20,184,120,0.3)] hover:shadow-[0_0_25px_rgba(20,184,120,0.5)] hover:-translate-y-0.5 transition-all duration-200 flex items-center gap-2"
        >
          <Plus className="w-4 h-4" /> New Scan
        </Link>
      </div>

      {/* Credits purchased banner */}
      {creditsPurchased && (
        <div className="mb-6 flex items-center gap-3 px-5 py-4 bg-primary/10 border border-primary/30 rounded-2xl text-sm text-primary">
          <ZapIcon className="w-5 h-5 shrink-0" />
          <span>
            <strong>Credits added!</strong> Your scan credits are now available. Select a scan tier below to use them.
          </span>
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-10">
        <div className="glass-card p-6 rounded-2xl flex flex-col gap-2">
          <div className="text-muted-foreground text-sm font-medium flex items-center gap-2">
            <RefreshCw className="w-4 h-4" /> Total Scans
          </div>
          <div className="text-4xl font-bold">{scans?.length ?? 0}</div>
        </div>

        <div className="glass-card p-6 rounded-2xl flex flex-col gap-2">
          <div className="text-muted-foreground text-sm font-medium flex items-center gap-2">
            <Shield className="w-4 h-4 text-emerald-400" /> Completed
          </div>
          <div className="text-4xl font-bold">{completedCount}</div>
        </div>

        <div className="glass-card p-6 rounded-2xl flex flex-col gap-2 relative overflow-hidden group">
          <div className="absolute inset-0 bg-gradient-to-br from-primary/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
          <div className="text-muted-foreground text-sm font-medium flex items-center gap-2 relative z-10">
            <ZapIcon className="w-4 h-4 text-primary" /> Available Credits
          </div>
          <div className="flex items-end justify-between relative z-10">
            <div className="text-4xl font-bold text-primary">{credits?.balance ?? 0}</div>
            <Link href="/scan" className="text-xs font-medium text-primary hover:underline underline-offset-4 pb-1">
              Get more &rarr;
            </Link>
          </div>
        </div>

        <Link
          href="/monitor"
          className={cn(
            "glass-card p-6 rounded-2xl flex flex-col gap-2 relative overflow-hidden group transition-colors hover:border-indigo-500/30",
            pendingCveAlerts > 0 && "border-red-400/30",
          )}
        >
          <div className="absolute inset-0 bg-gradient-to-br from-indigo-500/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
          <div className="text-muted-foreground text-sm font-medium flex items-center gap-2 relative z-10">
            <Bell className="w-4 h-4 text-indigo-400" /> Active Monitors
          </div>
          <div className="flex items-end justify-between relative z-10">
            <div className={cn("text-4xl font-bold", activeMonitors.length > 0 ? "text-indigo-400" : "")}>
              {activeMonitors.length}
            </div>
            {pendingCveAlerts > 0 ? (
              <div className="flex items-center gap-1 px-2 py-1 rounded-lg bg-red-400/10 border border-red-400/20 pb-1">
                <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                <span className="text-xs font-bold text-red-400">{pendingCveAlerts} CVE{pendingCveAlerts > 1 ? "s" : ""}</span>
              </div>
            ) : activeMonitors.length === 0 ? (
              <span className="text-xs font-medium text-indigo-400 hover:underline underline-offset-4 pb-1">
                Set up &rarr;
              </span>
            ) : (
              <span className="text-xs font-medium text-indigo-400 pb-1">
                Watching &rarr;
              </span>
            )}
          </div>
        </Link>
      </div>

      <CiIntegrationSection />

      {/* Scan table */}
      <div className="glass-panel rounded-2xl overflow-hidden">
        {scans && scans.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-white/10 bg-secondary/50">
                  <th className="p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Target</th>
                  <th className="p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider hidden sm:table-cell">Tier</th>
                  <th className="p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Status</th>
                  <th className="p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider hidden md:table-cell">Security</th>
                  <th className="p-4 text-right text-xs font-semibold text-muted-foreground uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <ScanRow
                    key={scan.id}
                    initialScan={scan}
                    highlight={scan.id === highlightScanId}
                  />
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-24 px-6 text-center flex flex-col items-center">
            <div className="w-16 h-16 bg-secondary rounded-2xl flex items-center justify-center mb-4 border border-white/5">
              <Shield className="w-8 h-8 text-muted-foreground opacity-50" />
            </div>
            <h3 className="text-xl font-bold mb-2">No scans yet</h3>
            <p className="text-muted-foreground max-w-sm mb-6">
              You haven&apos;t run any security scans yet. Launch your first scan to see how secure your app is.
            </p>
            <Link
              href="/scan"
              className="px-6 py-3 bg-secondary hover:bg-white/10 text-foreground font-semibold rounded-xl transition-colors border border-white/5 flex items-center gap-2"
            >
              Start your first scan <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        )}
      </div>
    </div>
  );
}
