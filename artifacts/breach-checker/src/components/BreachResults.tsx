import { BreachResult, BreachSource } from "@workspace/api-client-react";
import { ShieldCheck, ShieldAlert, AlertTriangle, AlertOctagon, Info, Database, Lock, Terminal, Activity, FileText } from "lucide-react";
import { format } from "date-fns";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Badge } from "@/components/ui/badge";

interface BreachResultsProps {
  result: BreachResult;
}

const RISK_COLORS = {
  safe: "text-green-500 bg-green-500/10 border-green-500/20",
  low: "text-yellow-500 bg-yellow-500/10 border-yellow-500/20",
  medium: "text-orange-500 bg-orange-500/10 border-orange-500/20",
  high: "text-red-500 bg-red-500/10 border-red-500/20",
  critical: "text-purple-500 bg-purple-500/10 border-purple-500/20",
};

const RISK_GAUGE_COLORS = {
  safe: "bg-green-500",
  low: "bg-yellow-500",
  medium: "bg-orange-500",
  high: "bg-red-500",
  critical: "bg-purple-500",
};

export function BreachResults({ result }: BreachResultsProps) {
  
  if (!result.found) {
    return (
      <div className="w-full bg-card border border-border rounded-xl p-8 flex flex-col items-center justify-center text-center space-y-6">
        <div className="relative">
          <div className="absolute inset-0 bg-green-500/20 blur-xl rounded-full animate-pulse-slow"></div>
          <div className="w-24 h-24 bg-green-500/10 border-2 border-green-500 rounded-full flex items-center justify-center relative z-10">
            <ShieldCheck className="w-12 h-12 text-green-500" />
          </div>
        </div>
        <div>
          <h2 className="text-3xl font-bold text-green-500 tracking-tight">SECURE</h2>
          <p className="text-muted-foreground mt-2 max-w-md mx-auto">
            No records of <span className="font-mono text-foreground">{result.query.value}</span> were found in our threat databases.
          </p>
        </div>
        
        {result.tips && result.tips.length > 0 && (
          <div className="w-full max-w-2xl mt-8 text-left bg-muted/50 p-6 rounded-lg border border-border">
            <h3 className="font-semibold flex items-center gap-2 mb-4">
              <ShieldAlert className="w-5 h-5 text-primary" />
              Proactive Security Measures
            </h3>
            <ul className="space-y-3">
              {result.tips.map((tip, idx) => (
                <li key={idx} className="flex items-start gap-3">
                  <div className="mt-1 w-1.5 h-1.5 rounded-full bg-primary shrink-0" />
                  <span className="text-sm text-muted-foreground">{tip}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    );
  }

  const formatNumber = (num: number | null | undefined) => {
    if (num == null) return "Unknown";
    return new Intl.NumberFormat().format(num);
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return "Unknown date";
    try {
      return format(new Date(dateStr), "MMMM yyyy");
    } catch {
      return dateStr;
    }
  };

  return (
    <div className="w-full flex flex-col gap-8">
      
      {/* Top Status Dashboard */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        
        {/* Main Risk Score Card */}
        <div className="col-span-1 md:col-span-2 bg-card border border-border rounded-xl p-6 flex flex-col sm:flex-row items-center gap-8">
          <div className="flex-1 w-full space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-mono text-muted-foreground uppercase tracking-widest">Threat Level</h3>
              <Badge variant="outline" className={`px-3 py-1 font-bold uppercase tracking-widest ${RISK_COLORS[result.riskLevel]}`}>
                {result.riskLevel} RISK
              </Badge>
            </div>
            
            <div className="space-y-2">
              <div className="flex justify-between items-end">
                <span className="text-5xl font-bold font-mono tracking-tighter">{result.riskScore}</span>
                <span className="text-muted-foreground text-sm font-mono mb-1">/ 100</span>
              </div>
              
              {/* Risk Gauge Bar */}
              <div className="h-4 w-full bg-muted rounded-full overflow-hidden flex">
                <div 
                  className={`h-full transition-all duration-1000 ease-out ${RISK_GAUGE_COLORS[result.riskLevel]}`}
                  style={{ width: `${result.riskScore}%` }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* Stats Column */}
        <div className="col-span-1 flex flex-col gap-4">
          <div className="bg-card border border-border rounded-xl p-4 flex flex-col justify-center flex-1">
            <span className="text-sm font-mono text-muted-foreground uppercase">Incidents</span>
            <span className="text-3xl font-bold font-mono">{formatNumber(result.totalBreaches)}</span>
          </div>
          <div className="bg-card border border-border rounded-xl p-4 flex flex-col justify-center flex-1">
            <span className="text-sm font-mono text-muted-foreground uppercase">Exposed Records</span>
            <span className="text-3xl font-bold font-mono text-destructive">{formatNumber(result.totalPwned)}</span>
          </div>
        </div>
      </div>

      {/* Query Target specific warning */}
      {result.query.type === "password" && (
        <div className="w-full bg-destructive/10 border border-destructive/30 rounded-xl p-6 flex items-start gap-4">
          <AlertOctagon className="w-8 h-8 text-destructive shrink-0" />
          <div>
            <h3 className="text-lg font-bold text-destructive">Password Compromised</h3>
            <p className="text-muted-foreground mt-1">
              This specific password has been seen <span className="font-mono font-bold text-foreground">{formatNumber(result.totalBreaches)}</span> times in known data breaches. 
              It is highly vulnerable to dictionary and credential stuffing attacks. Never use this password.
            </p>
          </div>
        </div>
      )}

      {/* Actionable Tips */}
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

      {/* Breach Sources List */}
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

function BreachCard({ source, formatNumber, formatDate }: { source: BreachSource, formatNumber: any, formatDate: any }) {
  
  const getDataTypeColor = (type: string) => {
    const lower = type.toLowerCase();
    if (lower.includes("password") || lower.includes("credential")) return "bg-red-500/20 text-red-400 border-red-500/30";
    if (lower.includes("email") || lower.includes("phone")) return "bg-blue-500/20 text-blue-400 border-blue-500/30";
    if (lower.includes("financial") || lower.includes("card") || lower.includes("bank")) return "bg-purple-500/20 text-purple-400 border-purple-500/30";
    if (lower.includes("ip") || lower.includes("location") || lower.includes("address")) return "bg-green-500/20 text-green-400 border-green-500/30";
    return "bg-secondary text-secondary-foreground border-border";
  };

  return (
    <div className="bg-card border border-border rounded-xl overflow-hidden hover:border-primary/50 transition-colors duration-300">
      <div className="p-6 flex flex-col md:flex-row gap-6">
        
        {/* Logo/Icon Area */}
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

        {/* Content Area */}
        <div className="flex-1 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
            <div>
              <h4 className="text-xl font-bold flex items-center gap-2">
                {source.title || source.name}
                {source.isVerified && (
                  <Badge variant="outline" className="bg-blue-500/10 text-blue-400 border-blue-500/20 px-1.5 py-0">Verified</Badge>
                )}
                {source.isSensitive && (
                  <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/20 px-1.5 py-0">Sensitive</Badge>
                )}
              </h4>
              <div className="flex items-center gap-3 text-sm text-muted-foreground mt-1 font-mono">
                <span>{formatDate(source.date)}</span>
                <span className="w-1 h-1 rounded-full bg-border" />
                <span>{formatNumber(source.pwnCount)} affected</span>
                {source.domain && (
                  <>
                    <span className="w-1 h-1 rounded-full bg-border" />
                    <span>{source.domain}</span>
                  </>
                )}
              </div>
            </div>
            
            <Badge variant="outline" className={`shrink-0 ${RISK_COLORS[source.riskLevel]} uppercase tracking-widest`}>
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
