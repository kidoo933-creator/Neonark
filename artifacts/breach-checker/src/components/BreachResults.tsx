import { BreachResult, BreachSource, BreachRemediation, PlatformPresence } from "@workspace/api-client-react";
import {
  ShieldCheck, ShieldAlert, AlertTriangle, AlertOctagon, Info,
  Database, Lock, Activity, Globe, Trash2, ExternalLink, CheckCircle2,
  XCircle, Star, Users
} from "lucide-react";
import { format } from "date-fns";
import {
  Accordion, AccordionContent, AccordionItem, AccordionTrigger,
} from "@/components/ui/accordion";
import { Badge } from "@/components/ui/badge";

interface BreachResultsProps {
  result: BreachResult;
}

// Grade → colors (higher score = greener)
const GRADE_CONFIG = {
  excellent: { label: "Excellent", color: "text-emerald-400", bg: "bg-emerald-500/10 border-emerald-500/30", bar: "bg-emerald-500", icon: ShieldCheck },
  good:      { label: "Good",      color: "text-green-400",   bg: "bg-green-500/10 border-green-500/30",   bar: "bg-green-500",   icon: ShieldCheck },
  fair:      { label: "Fair",      color: "text-yellow-400",  bg: "bg-yellow-500/10 border-yellow-500/30", bar: "bg-yellow-500",  icon: AlertTriangle },
  poor:      { label: "Poor",      color: "text-orange-400",  bg: "bg-orange-500/10 border-orange-500/30", bar: "bg-orange-400",  icon: AlertTriangle },
  critical:  { label: "Critical",  color: "text-red-400",     bg: "bg-red-500/10 border-red-500/30",       bar: "bg-red-500",     icon: AlertOctagon },
};

const SOURCE_RISK_COLORS: Record<string, string> = {
  low:      "text-green-400 bg-green-500/10 border-green-500/20",
  medium:   "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  high:     "text-orange-400 bg-orange-500/10 border-orange-500/20",
  critical: "text-red-400 bg-red-500/10 border-red-500/20",
};

export function BreachResults({ result }: BreachResultsProps) {
  const grade = (result.privacyGrade ?? "excellent") as keyof typeof GRADE_CONFIG;
  const gradeConfig = GRADE_CONFIG[grade] ?? GRADE_CONFIG.excellent;
  const score = result.privacyScore ?? 92;
  const GradeIcon = gradeConfig.icon;

  const formatNumber = (num: number | null | undefined) => {
    if (num == null) return "Unknown";
    return new Intl.NumberFormat().format(num);
  };

  const formatDate = (dateStr: string | null | undefined) => {
    if (!dateStr) return "Unknown date";
    try { return format(new Date(dateStr), "MMMM yyyy"); }
    catch { return dateStr; }
  };

  if (!result.found) {
    return (
      <div className="w-full bg-card border border-border rounded-xl p-8 flex flex-col items-center justify-center text-center space-y-6">
        <div className="relative">
          <div className="absolute inset-0 bg-emerald-500/20 blur-xl rounded-full animate-pulse-slow" />
          <div className="w-24 h-24 bg-emerald-500/10 border-2 border-emerald-500 rounded-full flex items-center justify-center relative z-10">
            <ShieldCheck className="w-12 h-12 text-emerald-500" />
          </div>
        </div>
        <div>
          <div className="flex items-center justify-center gap-3 mb-1">
            <span className="text-5xl font-bold font-mono text-emerald-400">{score}</span>
            <span className="text-muted-foreground font-mono">/100</span>
          </div>
          <h2 className="text-2xl font-bold text-emerald-500 tracking-tight">PRIVACY SCORE — {gradeConfig.label.toUpperCase()}</h2>
          <p className="text-muted-foreground mt-2 max-w-md mx-auto">
            No breach records found for <span className="font-mono text-foreground">{result.query.value}</span> in any monitored database.
          </p>
        </div>
        {result.tips && result.tips.length > 0 && (
          <div className="w-full max-w-2xl text-left bg-muted/50 p-6 rounded-lg border border-border">
            <h3 className="font-semibold flex items-center gap-2 mb-4">
              <ShieldAlert className="w-5 h-5 text-primary" />
              Proactive Security Measures
            </h3>
            <ul className="space-y-3">
              {result.tips.map((tip, idx) => (
                <li key={idx} className="flex items-start gap-3">
                  <div className="mt-1 w-1.5 h-1.5 rounded-full bg-emerald-400 shrink-0" />
                  <span className="text-sm text-muted-foreground">{tip}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
        {result.platformsFound && result.platformsFound.some((p) => p.exists) && (
          <PlatformSection platforms={result.platformsFound} />
        )}
      </div>
    );
  }

  return (
    <div className="w-full flex flex-col gap-8">

      {/* ── Privacy Score Dashboard ── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">

        {/* Main Score Card */}
        <div className={`col-span-1 md:col-span-2 bg-card border rounded-xl p-6 flex flex-col sm:flex-row items-center gap-8 ${gradeConfig.bg}`}>
          <div className="flex-1 w-full space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-mono text-muted-foreground uppercase tracking-widest">Privacy Score</h3>
              <Badge variant="outline" className={`px-3 py-1 font-bold uppercase tracking-widest ${gradeConfig.bg} ${gradeConfig.color}`}>
                <GradeIcon className="w-3.5 h-3.5 mr-1.5 inline" />
                {gradeConfig.label}
              </Badge>
            </div>

            <div className="space-y-2">
              <div className="flex justify-between items-end">
                <span className={`text-5xl font-bold font-mono tracking-tighter ${gradeConfig.color}`}>{score}</span>
                <span className="text-muted-foreground text-sm font-mono mb-1">/ 100 &nbsp;(higher = safer)</span>
              </div>

              {/* Score bar — fills green for high score, drains to red for low */}
              <div className="h-4 w-full bg-muted rounded-full overflow-hidden">
                <div
                  className={`h-full transition-all duration-1000 ease-out rounded-full ${gradeConfig.bar}`}
                  style={{ width: `${score}%` }}
                />
              </div>

              <p className="text-xs text-muted-foreground font-mono">
                {score >= 90 ? "No known threats detected" :
                 score >= 75 ? "Minor exposure — action recommended" :
                 score >= 50 ? "Moderate exposure — take action now" :
                 score >= 25 ? "Serious exposure — immediate action required" :
                 "Critical exposure — act immediately"}
              </p>
            </div>
          </div>
        </div>

        {/* Stats */}
        <div className="col-span-1 flex flex-col gap-4">
          <div className="bg-card border border-border rounded-xl p-4 flex flex-col justify-center flex-1">
            <span className="text-sm font-mono text-muted-foreground uppercase">Breach Sources</span>
            <span className="text-3xl font-bold font-mono">{formatNumber(result.totalBreaches)}</span>
          </div>
          <div className="bg-card border border-border rounded-xl p-4 flex flex-col justify-center flex-1">
            <span className="text-sm font-mono text-muted-foreground uppercase">Exposed Records</span>
            <span className={`text-3xl font-bold font-mono ${(result.totalPwned ?? 0) > 0 ? "text-orange-400" : "text-muted-foreground"}`}>
              {formatNumber(result.totalPwned)}
            </span>
          </div>
        </div>
      </div>

      {/* ── Password warning ── */}
      {result.query.type === "password" && result.found && (
        <div className="w-full bg-red-500/10 border border-red-500/30 rounded-xl p-6 flex items-start gap-4">
          <AlertOctagon className="w-8 h-8 text-red-400 shrink-0 mt-1" />
          <div>
            <h3 className="text-lg font-bold text-red-400">Password Compromised</h3>
            <p className="text-muted-foreground mt-1">
              This password has been seen <span className="font-mono font-bold text-foreground">{formatNumber(result.totalPwned)}</span> times in breach databases.
              {result.isCommonPassword && " It also appears on the RockYou wordlist — used in every dictionary attack."}
              {" "}Never use this password anywhere.
            </p>
          </div>
        </div>
      )}

      {/* ── RockYou warning ── */}
      {result.isCommonPassword && result.query.type !== "password" && (
        <div className="w-full bg-red-500/10 border border-red-500/30 rounded-xl p-5 flex items-start gap-4">
          <Lock className="w-6 h-6 text-red-400 shrink-0 mt-0.5" />
          <div>
            <h3 className="font-bold text-red-400">Found on RockYou Wordlist</h3>
            <p className="text-sm text-muted-foreground mt-1">This is one of the most commonly used passwords in the world. Attackers try it automatically. Change it everywhere immediately.</p>
          </div>
        </div>
      )}

      {/* ── Platform Presence ── */}
      {result.platformsFound && result.platformsFound.length > 0 && (
        <PlatformSection platforms={result.platformsFound} />
      )}

      {/* ── Recommended Actions ── */}
      {result.tips && result.tips.length > 0 && (
        <div className="w-full bg-secondary/30 border border-border rounded-xl p-6">
          <h3 className="text-lg font-semibold flex items-center gap-2 mb-4">
            <ShieldAlert className="w-5 h-5 text-primary" />
            Recommended Actions
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {result.tips.map((tip, idx) => (
              <div key={idx} className="flex items-start gap-3 bg-card border border-border/50 p-4 rounded-lg">
                <Activity className="w-5 h-5 text-primary shrink-0 mt-0.5" />
                <span className="text-sm text-foreground/90">{tip}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Data Removal Guide ── */}
      {result.remediation && result.remediation.length > 0 && (
        <div className="w-full bg-secondary/20 border border-border rounded-xl p-6">
          <h3 className="text-lg font-semibold flex items-center gap-2 mb-5">
            <Trash2 className="w-5 h-5 text-primary" />
            How to Remove Your Data
          </h3>
          <div className="space-y-3">
            {result.remediation.map((rem, idx) => (
              <RemediationCard key={idx} rem={rem} />
            ))}
          </div>
        </div>
      )}

      {/* ── Breach Sources ── */}
      {result.sources.length > 0 && (
        <div className="space-y-4">
          <h3 className="text-xl font-bold font-mono uppercase tracking-widest text-muted-foreground flex items-center gap-2">
            <Database className="w-5 h-5" />
            Identified Breaches
          </h3>
          <div className="grid grid-cols-1 gap-4">
            {result.sources.map((source, idx) => (
              <BreachCard key={idx} source={source} formatNumber={formatNumber} formatDate={formatDate} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function PlatformSection({ platforms }: { platforms: PlatformPresence[] }) {
  const found = platforms.filter((p) => p.exists);
  const notFound = platforms.filter((p) => !p.exists);
  return (
    <div className="w-full bg-card border border-border rounded-xl p-6">
      <h3 className="font-semibold flex items-center gap-2 mb-4">
        <Globe className="w-5 h-5 text-primary" />
        Platform Presence Check
      </h3>
      <p className="text-sm text-muted-foreground mb-4">
        Checked if your credentials are publicly registered on major platforms.
        {found.length === 0
          ? " No public accounts found — excellent for privacy."
          : ` Found on ${found.length} platform${found.length !== 1 ? "s" : ""}. Each active account is a potential attack surface.`}
      </p>
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        {platforms.map((p, idx) => (
          <div key={idx} className={`flex items-center gap-3 p-3 rounded-lg border ${p.exists ? "bg-orange-500/5 border-orange-500/20" : "bg-muted/30 border-border"}`}>
            {p.exists
              ? <XCircle className="w-4 h-4 text-orange-400 shrink-0" />
              : <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />}
            <div className="min-w-0">
              <div className="font-medium text-sm truncate">{p.name}</div>
              <div className={`text-xs ${p.exists ? "text-orange-400" : "text-emerald-500"}`}>
                {p.exists ? "Account found" : "Not found"}
              </div>
            </div>
            {p.exists && (
              <a href={p.url} target="_blank" rel="noopener noreferrer" className="ml-auto shrink-0">
                <ExternalLink className="w-3.5 h-3.5 text-muted-foreground hover:text-foreground" />
              </a>
            )}
          </div>
        ))}
      </div>
      {found.length > 0 && (
        <p className="text-xs text-muted-foreground mt-4 flex items-center gap-1.5">
          <Info className="w-3.5 h-3.5 shrink-0" />
          Major platforms (GitHub, Reddit) are generally secure but a public profile reduces privacy. Obscure or unknown platforms are higher risk.
        </p>
      )}
    </div>
  );
}

function RemediationCard({ rem }: { rem: BreachRemediation }) {
  return (
    <Accordion type="single" collapsible className="w-full">
      <AccordionItem value="rem" className="border border-border rounded-lg overflow-hidden bg-card">
        <AccordionTrigger className="px-4 py-3 text-sm font-semibold hover:no-underline hover:bg-muted/50">
          <div className="flex items-center gap-2">
            <Trash2 className="w-4 h-4 text-orange-400 shrink-0" />
            Remove your data from {rem.service}
            {rem.breachDate && (
              <span className="text-xs text-muted-foreground font-normal ml-2">
                (breached {new Date(rem.breachDate).toLocaleDateString("en-US", { month: "short", year: "numeric" })})
              </span>
            )}
          </div>
        </AccordionTrigger>
        <AccordionContent className="px-4 pt-2 pb-4 space-y-3">
          <ol className="space-y-2">
            {rem.steps.map((step, i) => (
              <li key={i} className="flex items-start gap-3 text-sm text-foreground/80">
                <span className="shrink-0 w-5 h-5 rounded-full bg-primary/20 text-primary text-xs flex items-center justify-center font-mono font-bold mt-0.5">
                  {i + 1}
                </span>
                {step}
              </li>
            ))}
          </ol>
          {rem.dataDeleteUrl && (
            <a
              href={rem.dataDeleteUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-xs text-primary hover:underline mt-2"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              Go to {rem.service} privacy settings →
            </a>
          )}
        </AccordionContent>
      </AccordionItem>
    </Accordion>
  );
}

function BreachCard({ source, formatNumber, formatDate }: {
  source: BreachSource;
  formatNumber: (n: number | null | undefined) => string;
  formatDate: (s: string | null | undefined) => string;
}) {
  const getDataTypeColor = (type: string) => {
    const lower = type.toLowerCase();
    if (lower.includes("password") || lower.includes("credential")) return "bg-red-500/20 text-red-400 border-red-500/30";
    if (lower.includes("email") || lower.includes("phone")) return "bg-blue-500/20 text-blue-400 border-blue-500/30";
    if (lower.includes("financial") || lower.includes("card") || lower.includes("bank")) return "bg-purple-500/20 text-purple-400 border-purple-500/30";
    if (lower.includes("social security") || lower.includes("ssn")) return "bg-red-600/20 text-red-300 border-red-600/30";
    if (lower.includes("ip") || lower.includes("location") || lower.includes("address")) return "bg-green-500/20 text-green-400 border-green-500/30";
    return "bg-secondary text-secondary-foreground border-border";
  };

  return (
    <div className="bg-card border border-border rounded-xl overflow-hidden hover:border-primary/40 transition-colors duration-300">
      <div className="p-6 flex flex-col md:flex-row gap-6">
        <div className="shrink-0 flex items-start justify-center md:justify-start">
          {source.logoPath ? (
            <div className="w-16 h-16 rounded bg-white p-1 overflow-hidden shrink-0">
              <img src={source.logoPath} alt={`${source.name} logo`} className="w-full h-full object-contain" />
            </div>
          ) : (
            <div className="w-16 h-16 rounded bg-muted flex items-center justify-center shrink-0 border border-border">
              <Database className="w-8 h-8 text-muted-foreground" />
            </div>
          )}
        </div>

        <div className="flex-1 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
            <div>
              <h4 className="text-xl font-bold flex items-center gap-2">
                {source.title || source.name}
                {source.isVerified && (
                  <Badge variant="outline" className="bg-blue-500/10 text-blue-400 border-blue-500/20 px-1.5 py-0 text-xs">Verified</Badge>
                )}
                {source.isSensitive && (
                  <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/20 px-1.5 py-0 text-xs">Sensitive</Badge>
                )}
              </h4>
              <div className="flex flex-wrap items-center gap-3 text-sm text-muted-foreground mt-1 font-mono">
                <span>{formatDate(source.date)}</span>
                {source.pwnCount != null && (
                  <>
                    <span className="w-1 h-1 rounded-full bg-border" />
                    <span className="flex items-center gap-1"><Users className="w-3.5 h-3.5" />{formatNumber(source.pwnCount)} affected</span>
                  </>
                )}
                {source.domain && (
                  <>
                    <span className="w-1 h-1 rounded-full bg-border" />
                    <span>{source.domain}</span>
                  </>
                )}
              </div>
            </div>
            <Badge variant="outline" className={`shrink-0 uppercase tracking-widest text-xs ${SOURCE_RISK_COLORS[source.riskLevel]}`}>
              {source.riskLevel}
            </Badge>
          </div>

          <div className="flex flex-wrap gap-2">
            {source.dataClasses.map((type, i) => (
              <Badge key={i} variant="outline" className={`font-mono text-xs ${getDataTypeColor(type)}`}>
                {type}
              </Badge>
            ))}
          </div>

          {source.description && (
            <Accordion type="single" collapsible className="w-full border-none">
              <AccordionItem value="details" className="border-none">
                <AccordionTrigger className="text-sm text-muted-foreground hover:text-foreground py-2 font-mono">
                  View Incident Details
                </AccordionTrigger>
                <AccordionContent className="text-sm text-foreground/80 leading-relaxed pt-2">
                  <div dangerouslySetInnerHTML={{ __html: source.description }} className="prose prose-sm dark:prose-invert max-w-none" />
                </AccordionContent>
              </AccordionItem>
            </Accordion>
          )}
        </div>
      </div>
    </div>
  );
}
