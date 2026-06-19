import { useState } from "react";
import { useCheckBreach } from "@workspace/api-client-react";
import { Scanner } from "@/components/Scanner";
import { BreachResults } from "@/components/BreachResults";
import { BreachEncyclopedia } from "@/components/BreachEncyclopedia";
import { Shield } from "lucide-react";

export default function Home() {
  const checkBreach = useCheckBreach();

  const handleSearch = (type: any, value: string) => {
    checkBreach.mutate({
      data: { type, value },
    });
  };

  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col selection:bg-primary/30">
      
      {/* Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 h-16 flex items-center gap-2">
          <Shield className="w-6 h-6 text-primary" />
          <span className="font-bold text-lg tracking-tight">GuardianScan</span>
          <span className="text-xs font-mono text-muted-foreground ml-2 px-2 py-0.5 rounded-full bg-muted border border-border">v1.0.0</span>
        </div>
      </header>

      <main className="flex-1 container mx-auto px-4 py-12 max-w-5xl flex flex-col gap-12">
        
        {/* Hero Section */}
        <section className="flex flex-col items-center text-center gap-4 max-w-2xl mx-auto mb-8">
          <h1 className="text-4xl md:text-5xl font-bold tracking-tight">
            Intelligence for your digital footprint.
          </h1>
          <p className="text-muted-foreground text-lg">
            Search across billions of records to uncover if your personal data has been compromised in known security breaches.
          </p>
        </section>

        {/* Search / Scanner */}
        <section className="w-full flex justify-center">
          <Scanner 
            onSearch={handleSearch} 
            isScanning={checkBreach.isPending} 
          />
        </section>

        {/* Results */}
        {checkBreach.data && (
          <section className="w-full animate-in fade-in slide-in-from-bottom-8 duration-700">
            <BreachResults result={checkBreach.data} />
          </section>
        )}

        <div className="w-full h-px bg-border my-8" />

        {/* Encyclopedia */}
        <section className="w-full">
          <BreachEncyclopedia />
        </section>

      </main>

      <footer className="border-t border-border py-8 mt-12 bg-card">
        <div className="container mx-auto px-4 text-center text-sm text-muted-foreground font-mono">
          GuardianScan System &bull; Secure Databanks &bull; Stay Vigilant
        </div>
      </footer>
    </div>
  );
}
