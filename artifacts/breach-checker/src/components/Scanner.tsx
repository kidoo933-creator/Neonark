import { useState } from "react";
import { Mail, Phone, User, Globe, Key, Hash, Search, Eye, EyeOff, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { BreachQueryType } from "@workspace/api-client-react";

interface ScannerProps {
  onSearch: (type: BreachQueryType, value: string) => void;
  isScanning: boolean;
}

const SEARCH_TYPES = [
  { id: BreachQueryType.email, label: "Email", icon: Mail, placeholder: "target@example.com" },
  { id: BreachQueryType.phone, label: "Phone", icon: Phone, placeholder: "+1 (555) 000-0000" },
  { id: BreachQueryType.username, label: "Username", icon: User, placeholder: "johndoe123" },
  { id: BreachQueryType.password, label: "Password", icon: Key, placeholder: "hunter2" },
  { id: BreachQueryType.ip, label: "IP Address", icon: Hash, placeholder: "192.168.1.1" },
  { id: BreachQueryType.domain, label: "Domain", icon: Globe, placeholder: "example.com" },
];

export function Scanner({ onSearch, isScanning }: ScannerProps) {
  const [activeType, setActiveType] = useState<BreachQueryType>(BreachQueryType.email);
  const [value, setValue] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  const activeConfig = SEARCH_TYPES.find(t => t.id === activeType)!;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!value.trim() || isScanning) return;
    onSearch(activeType, value.trim());
  };

  return (
    <div className="w-full max-w-3xl flex flex-col gap-6">
      
      {/* Type Selector */}
      <div className="flex flex-wrap items-center justify-center gap-2 p-1 bg-card border border-border rounded-xl">
        {SEARCH_TYPES.map((type) => {
          const Icon = type.icon;
          const isActive = activeType === type.id;
          return (
            <button
              key={type.id}
              onClick={() => {
                setActiveType(type.id as BreachQueryType);
                setValue("");
                setShowPassword(false);
              }}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
                isActive 
                  ? "bg-primary text-primary-foreground shadow-md" 
                  : "text-muted-foreground hover:bg-muted hover:text-foreground"
              }`}
            >
              <Icon className="w-4 h-4" />
              <span className="hidden sm:inline">{type.label}</span>
            </button>
          );
        })}
      </div>

      {/* Input Area */}
      <form onSubmit={handleSubmit} className="relative group">
        
        {/* Scanning visual effect */}
        {isScanning && (
          <div className="absolute inset-0 z-20 pointer-events-none overflow-hidden rounded-xl">
            <div className="w-full h-full bg-primary/5 absolute top-0 left-0" />
            <div className="w-full h-[2px] bg-primary shadow-[0_0_8px_2px_rgba(var(--primary),0.5)] animate-scan" />
          </div>
        )}

        <div className={`relative flex items-center bg-card border-2 transition-colors duration-300 rounded-xl overflow-hidden ${
          isScanning ? "border-primary shadow-[0_0_15px_rgba(var(--primary),0.3)]" : "border-border hover:border-muted-foreground/50 focus-within:border-primary"
        }`}>
          
          <div className="pl-4 pr-2 text-muted-foreground">
            <activeConfig.icon className="w-5 h-5" />
          </div>

          <Input
            type={activeType === BreachQueryType.password && !showPassword ? "password" : "text"}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={activeConfig.placeholder}
            className="flex-1 border-0 focus-visible:ring-0 px-2 py-6 text-lg bg-transparent shadow-none"
            disabled={isScanning}
          />

          {activeType === BreachQueryType.password && (
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="px-3 text-muted-foreground hover:text-foreground transition-colors"
            >
              {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
            </button>
          )}

          <div className="pr-2">
            <Button 
              type="submit" 
              size="lg"
              disabled={!value.trim() || isScanning}
              className="px-8"
            >
              {isScanning ? (
                <span className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 animate-pulse" />
                  Scanning...
                </span>
              ) : (
                <span className="flex items-center gap-2">
                  <Search className="w-4 h-4" />
                  Analyze
                </span>
              )}
            </Button>
          </div>
        </div>

      </form>
    </div>
  );
}
