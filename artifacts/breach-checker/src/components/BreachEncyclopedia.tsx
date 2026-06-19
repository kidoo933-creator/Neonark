import { useState } from "react";
import { useGetBreachCatalog, useGetBreachStats } from "@workspace/api-client-react";
import { Database, Shield, Server, ArrowUpDown, Search } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { format } from "date-fns";

export function BreachEncyclopedia() {
  const { data: stats, isLoading: statsLoading } = useGetBreachStats();
  const { data: catalog, isLoading: catalogLoading } = useGetBreachCatalog();
  const [searchTerm, setSearchTerm] = useState("");

  const formatNumber = (num: number) => new Intl.NumberFormat().format(num);
  
  const formatDate = (dateStr: string) => {
    try {
      return format(new Date(dateStr), "MMM yyyy");
    } catch {
      return dateStr;
    }
  };

  const filteredCatalog = catalog?.filter(entry => 
    entry.name.toLowerCase().includes(searchTerm.toLowerCase()) || 
    entry.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
    entry.domain?.toLowerCase().includes(searchTerm.toLowerCase())
  ) || [];

  return (
    <div className="w-full flex flex-col gap-8">
      
      <div className="flex flex-col gap-2">
        <h2 className="text-2xl font-bold font-mono tracking-tight flex items-center gap-3">
          <Server className="w-6 h-6 text-primary" />
          Global Threat Intelligence
        </h2>
        <p className="text-muted-foreground">Comprehensive database of known data breaches and exposures.</p>
      </div>

      {/* Stats Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
        {statsLoading || !stats ? (
          Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-24 rounded-xl" />)
        ) : (
          <>
            <StatCard title="Tracked Breaches" value={formatNumber(stats.totalBreaches)} />
            <StatCard title="Compromised Accounts" value={formatNumber(stats.totalPwnedAccounts)} valueClass="text-destructive" />
            <StatCard title="Largest Breach" value={stats.largestBreach.name} subtitle={`${formatNumber(stats.largestBreach.pwnCount)} records`} />
            <StatCard title="Newest Entry" value={stats.newestBreach.name} subtitle={formatDate(stats.newestBreach.date)} />
          </>
        )}
      </div>

      {/* Catalog Section */}
      <div className="bg-card border border-border rounded-xl overflow-hidden flex flex-col">
        <div className="p-4 border-b border-border bg-secondary/20 flex flex-col sm:flex-row items-center justify-between gap-4">
          <h3 className="font-semibold">Breach Catalog</h3>
          <div className="relative w-full sm:w-72">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <Input 
              placeholder="Search breaches..." 
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-9 bg-background"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-xs text-muted-foreground uppercase bg-secondary/10 border-b border-border font-mono">
              <tr>
                <th className="px-6 py-4 font-medium">Organization</th>
                <th className="px-6 py-4 font-medium">Domain</th>
                <th className="px-6 py-4 font-medium">Date</th>
                <th className="px-6 py-4 font-medium">Impact</th>
                <th className="px-6 py-4 font-medium">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {catalogLoading ? (
                Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i}>
                    <td className="px-6 py-4"><Skeleton className="h-5 w-32" /></td>
                    <td className="px-6 py-4"><Skeleton className="h-5 w-24" /></td>
                    <td className="px-6 py-4"><Skeleton className="h-5 w-20" /></td>
                    <td className="px-6 py-4"><Skeleton className="h-5 w-16" /></td>
                    <td className="px-6 py-4"><Skeleton className="h-5 w-12" /></td>
                  </tr>
                ))
              ) : filteredCatalog.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-6 py-12 text-center text-muted-foreground">
                    No breaches found matching your search.
                  </td>
                </tr>
              ) : (
                // Only render first 50 to avoid massive DOM issues if unchecked
                filteredCatalog.slice(0, 50).map((entry, idx) => (
                  <tr key={idx} className="hover:bg-muted/50 transition-colors">
                    <td className="px-6 py-4 font-medium flex items-center gap-3">
                      {entry.logoPath ? (
                        <img src={entry.logoPath} alt="" className="w-6 h-6 rounded bg-white p-0.5 object-contain" />
                      ) : (
                        <Database className="w-6 h-6 text-muted-foreground" />
                      )}
                      {entry.title}
                    </td>
                    <td className="px-6 py-4 text-muted-foreground">{entry.domain || "-"}</td>
                    <td className="px-6 py-4 font-mono">{formatDate(entry.breachDate)}</td>
                    <td className="px-6 py-4 font-mono text-destructive">{formatNumber(entry.pwnCount)}</td>
                    <td className="px-6 py-4">
                      <div className="flex gap-2">
                        {entry.isVerified && <Badge variant="outline" className="bg-blue-500/10 text-blue-400 border-blue-500/20 text-[10px]">Verified</Badge>}
                        {entry.isSensitive && <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/20 text-[10px]">Sensitive</Badge>}
                        {!entry.isVerified && !entry.isSensitive && <span className="text-muted-foreground">-</span>}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
          
          {filteredCatalog.length > 50 && (
            <div className="p-4 text-center text-sm text-muted-foreground border-t border-border bg-secondary/10">
              Showing 50 of {formatNumber(filteredCatalog.length)} results. Use search to find specific breaches.
            </div>
          )}
        </div>
      </div>

    </div>
  );
}

function StatCard({ title, value, subtitle, valueClass = "" }: { title: string, value: string, subtitle?: string, valueClass?: string }) {
  return (
    <div className="bg-card border border-border rounded-xl p-5 flex flex-col justify-center">
      <span className="text-xs font-mono text-muted-foreground uppercase mb-2">{title}</span>
      <span className={`text-2xl font-bold font-mono ${valueClass}`}>{value}</span>
      {subtitle && <span className="text-xs text-muted-foreground mt-1">{subtitle}</span>}
    </div>
  );
}
