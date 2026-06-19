import { Router, type IRouter } from "express";
import crypto from "crypto";
import { CheckBreachBody } from "@workspace/api-zod";

const router: IRouter = Router();

// ─── Types ────────────────────────────────────────────────────────────────────

interface HibpBreach {
  Name: string;
  Title: string;
  Domain: string;
  BreachDate: string;
  AddedDate: string;
  PwnCount: number;
  Description: string;
  LogoPath: string;
  DataClasses: string[];
  IsVerified: boolean;
  IsFabricated: boolean;
  IsSensitive: boolean;
  IsRetired: boolean;
  IsSpamList: boolean;
}

interface LeakCheckSource {
  name: string;
  date?: string;
}

interface LeakCheckResult {
  success: boolean;
  found: number;
  sources?: LeakCheckSource[];
  fields?: string[];
}

// ─── Catalog cache ────────────────────────────────────────────────────────────

let catalogCache: HibpBreach[] | null = null;
let catalogCacheTime = 0;
const CACHE_TTL_MS = 60 * 60 * 1000;

async function fetchCatalog(): Promise<HibpBreach[]> {
  const now = Date.now();
  if (catalogCache && now - catalogCacheTime < CACHE_TTL_MS) return catalogCache;
  const res = await fetch("https://haveibeenpwned.com/api/v3/breaches", {
    headers: { "User-Agent": "GuardianScan/1.0" },
  });
  if (!res.ok) throw new Error(`HIBP catalog error: ${res.status}`);
  catalogCache = (await res.json()) as HibpBreach[];
  catalogCacheTime = Date.now();
  return catalogCache;
}

// ─── HIBP k-anonymity password check ──────────────────────────────────────────

async function checkPasswordHibp(password: string): Promise<{ found: boolean; count: number }> {
  const hash = crypto.createHash("sha1").update(password).digest("hex").toUpperCase();
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { "User-Agent": "GuardianScan/1.0", "Add-Padding": "true" },
  });
  if (!res.ok) throw new Error(`HIBP Passwords error: ${res.status}`);
  const text = await res.text();
  for (const line of text.split("\n")) {
    const [hashSuffix, countStr] = line.split(":");
    if (hashSuffix?.trim() === suffix) {
      return { found: true, count: parseInt(countStr?.trim() ?? "0", 10) };
    }
  }
  return { found: false, count: 0 };
}

// ─── LeakCheck.io free public API ─────────────────────────────────────────────
// Returns real per-email/username/phone breach sources (no key required)

async function checkLeakCheck(query: string): Promise<LeakCheckResult | null> {
  try {
    const res = await fetch(
      `https://leakcheck.io/api/public?check=${encodeURIComponent(query)}`,
      {
        headers: { "User-Agent": "GuardianScan/1.0", Accept: "application/json" },
        signal: AbortSignal.timeout(8000),
      }
    );
    if (!res.ok) return null;
    return (await res.json()) as LeakCheckResult;
  } catch {
    return null;
  }
}

// ─── Risk helpers ─────────────────────────────────────────────────────────────

function sourceRiskLevel(breach: HibpBreach): "low" | "medium" | "high" | "critical" {
  const dc = breach.DataClasses.map((d) => d.toLowerCase());
  if (
    breach.IsSensitive ||
    dc.some((d) =>
      d.includes("credit") || d.includes("bank") || d.includes("ssn") ||
      d.includes("passport") || d.includes("social security") || d.includes("tax")
    )
  ) return "critical";
  if (dc.some((d) => d.includes("password") || d.includes("pin"))) return "high";
  if (dc.some((d) => d.includes("phone") || d.includes("address") || d.includes("date of birth")))
    return "medium";
  return "low";
}

function riskLevelFromScore(score: number): "safe" | "low" | "medium" | "high" | "critical" {
  if (score === 0) return "safe";
  if (score <= 20) return "low";
  if (score <= 45) return "medium";
  if (score <= 70) return "high";
  return "critical";
}

// Convert LeakCheck field names to human-readable data class names
function fieldsToDataClasses(fields: string[]): string[] {
  const map: Record<string, string> = {
    password: "Passwords", email: "Email addresses", phone: "Phone numbers",
    username: "Usernames", name: "Names", first_name: "Names", last_name: "Names",
    address: "Physical addresses", address1: "Physical addresses",
    dob: "Dates of birth", ip: "IP addresses", ip1: "IP addresses", ip2: "IP addresses",
    ssn: "Social security numbers", credit_card: "Credit card data",
    gender: "Genders", location: "Geographic locations", city: "Geographic locations",
    country: "Geographic locations", state: "Geographic locations",
    zip: "ZIP codes", province: "Geographic locations", region: "Geographic locations",
    profile_name: "Usernames", origin: "Geographic locations",
    company_name: "Employers", qqmail: "Email addresses",
  };
  const result = new Set<string>();
  for (const f of fields) {
    const mapped = map[f.toLowerCase()];
    if (mapped) result.add(mapped);
    else result.add(f.charAt(0).toUpperCase() + f.slice(1).replace(/_/g, " "));
  }
  return [...result];
}

function buildHibpSource(b: HibpBreach) {
  return {
    name: b.Name,
    title: b.Title || null,
    date: b.BreachDate || null,
    addedDate: b.AddedDate || null,
    domain: b.Domain || null,
    dataClasses: b.DataClasses,
    pwnCount: b.PwnCount || null,
    description: b.Description || null,
    logoPath: b.LogoPath || null,
    isVerified: b.IsVerified,
    isSensitive: b.IsSensitive,
    riskLevel: sourceRiskLevel(b),
  };
}

// Build a minimal source entry for LeakCheck sources not found in HIBP catalog
function buildLeakCheckStub(src: LeakCheckSource, dataClasses: string[]) {
  const hasPassword = dataClasses.some((d) => d.toLowerCase().includes("password"));
  const hasSensitive = dataClasses.some((d) =>
    d.toLowerCase().includes("ssn") || d.toLowerCase().includes("credit")
  );
  const hasPhone = dataClasses.some((d) => d.toLowerCase().includes("phone"));
  let riskLevel: "low" | "medium" | "high" | "critical" = "low";
  if (hasSensitive) riskLevel = "critical";
  else if (hasPassword) riskLevel = "high";
  else if (hasPhone) riskLevel = "medium";

  const cleanName = src.name.replace(/\.(com|net|org|io|me|fr|vn|ru|de|uk|in)$/i, "");
  const domain = src.name.includes(".") ? src.name : null;
  const dateStr = src.date ? (src.date.length === 7 ? src.date + "-01" : src.date) : null;

  return {
    name: cleanName,
    title: cleanName,
    date: dateStr,
    addedDate: null,
    domain,
    dataClasses,
    pwnCount: null,
    description: `This service was identified as a breach source by LeakCheck OSINT database. Your data was exposed here${dateStr ? " on or around " + new Date(dateStr).toLocaleDateString("en-US", { month: "long", year: "numeric" }) : ""}.`,
    logoPath: null,
    isVerified: true,
    isSensitive: hasSensitive,
    riskLevel,
  };
}

// Match LeakCheck source names to HIBP catalog entries
function matchToCatalog(sources: LeakCheckSource[], catalog: HibpBreach[]): {
  matched: HibpBreach[];
  unmatched: LeakCheckSource[];
} {
  const matched: HibpBreach[] = [];
  const unmatched: LeakCheckSource[] = [];
  const usedNames = new Set<string>();

  for (const src of sources) {
    const raw = src.name.toLowerCase();
    const stripped = raw.replace(/\.(com|net|org|io|me|fr|vn|ru|de|uk|in|co)$/i, "").replace(/[^a-z0-9]/g, "");

    let found = catalog.find((b) => {
      const bn = b.Name.toLowerCase().replace(/[^a-z0-9]/g, "");
      const bt = b.Title.toLowerCase().replace(/[^a-z0-9]/g, "");
      const bd = b.Domain?.toLowerCase().replace(/[^a-z0-9]/g, "") ?? "";
      return bn === stripped || bt === stripped || bd === stripped || bd.startsWith(stripped) || stripped.startsWith(bn);
    });

    if (!found) {
      found = catalog.find((b) =>
        b.Domain?.toLowerCase() === raw || b.Domain?.toLowerCase().replace("www.", "") === raw
      );
    }

    if (found && !usedNames.has(found.Name)) {
      matched.push(found);
      usedNames.add(found.Name);
    } else if (!found) {
      unmatched.push(src);
    }
  }
  return { matched, unmatched };
}

// Compute risk score based purely on real signals
function computeRiskFromLeakCheck(
  confirmed: boolean,
  foundCount: number,
  fields: string[],
  hibpMatches: HibpBreach[],
  unmatchedCount: number
): number {
  if (!confirmed) return 0;

  const fl = fields.map((f) => f.toLowerCase());
  let score = 15; // base: confirmed

  // Scale by record count
  if (foundCount > 10000) score += 25;
  else if (foundCount > 1000) score += 20;
  else if (foundCount > 100) score += 15;
  else if (foundCount > 0) score += 10;

  // Penalize based on exposed field types
  if (fl.some((f) => f.includes("password"))) score += 20;
  if (fl.some((f) => f.includes("ssn") || f.includes("social"))) score += 15;
  if (fl.some((f) => f.includes("credit") || f.includes("bank"))) score += 15;
  if (fl.some((f) => f.includes("phone"))) score += 5;
  if (fl.some((f) => f.includes("dob"))) score += 5;

  // HIBP matches with high-risk data
  for (const b of hibpMatches) {
    if (b.IsSensitive) score += 5;
    if (sourceRiskLevel(b) === "critical") score += 3;
    if (sourceRiskLevel(b) === "high") score += 2;
  }

  // Extra sources
  score += Math.min(unmatchedCount * 2, 10);

  return Math.min(score, 100);
}

// Generate personalized tips from confirmed breach data
function buildTips(
  hibpBreaches: HibpBreach[],
  leakCheckFields: string[],
  queryType: string,
  confirmed: boolean
): string[] {
  const tips: string[] = [];
  const fl = leakCheckFields.map((f) => f.toLowerCase());
  const allDc = [...new Set(hibpBreaches.flatMap((b) => b.DataClasses.map((d) => d.toLowerCase())))];
  const hasPasswords = fl.includes("password") || allDc.some((d) => d.includes("password"));
  const hasPhone = fl.includes("phone") || allDc.some((d) => d.includes("phone"));
  const hasSsn = fl.some((f) => f.includes("ssn")) || allDc.some((d) => d.includes("social security"));
  const hasFinancial = fl.some((f) => f.includes("credit") || f.includes("bank")) ||
    allDc.some((d) => d.includes("credit") || d.includes("bank"));

  // Per-breach specific tips (top 3 by severity)
  const sorted = [...hibpBreaches].sort((a, b) => {
    const rl = { critical: 4, high: 3, medium: 2, low: 1 };
    return rl[sourceRiskLevel(b)] - rl[sourceRiskLevel(a)];
  });

  for (const b of sorted.slice(0, 3)) {
    const dc = b.DataClasses;
    const dateStr = b.BreachDate
      ? new Date(b.BreachDate).toLocaleDateString("en-US", { month: "long", year: "numeric" })
      : null;
    const service = b.Title || b.Name;
    const domainStr = b.Domain ? ` (${b.Domain})` : "";
    const pwned = b.PwnCount ? b.PwnCount.toLocaleString() : "millions of";
    const bHasPassword = dc.some((d) => d.toLowerCase().includes("password"));
    const bHasFinancial = dc.some((d) => d.toLowerCase().includes("credit") || d.toLowerCase().includes("bank"));
    const bHasPhone = dc.some((d) => d.toLowerCase().includes("phone"));

    if (bHasPassword && dateStr) {
      tips.push(`Change your ${service}${domainStr} password now — breached ${dateStr}, ${pwned} accounts exposed. Update any other account using the same password.`);
    } else if (bHasFinancial && dateStr) {
      tips.push(`Financial data exposed in the ${service} breach (${dateStr}). Check your statements for unauthorized charges and place a fraud alert with credit bureaus.`);
    } else if (bHasPhone && dateStr) {
      tips.push(`Phone number exposed in the ${service} breach (${dateStr}). Call your carrier and add a SIM-lock PIN to block SIM-swap attacks.`);
    } else if (dateStr) {
      tips.push(`${service} breach (${dateStr}) exposed: ${dc.slice(0, 3).join(", ")}. Log in and change your credentials — enable 2FA if available.`);
    }
  }

  if (hasPasswords && tips.length < 5)
    tips.push("Use a password manager (Bitwarden is free) to generate unique passwords for every account. Reusing passwords multiplies breach damage.");
  if (confirmed && tips.length < 5)
    tips.push("Enable two-factor authentication on email, banking, and social accounts. A stolen password cannot log in without the second factor.");
  if (hasSsn)
    tips.push("Social Security Number was exposed. Freeze your credit at Equifax, Experian, and TransUnion immediately. File an identity theft report at identitytheft.gov.");
  if (hasFinancial && !hasSsn)
    tips.push("Financial data was exposed. Monitor bank statements and set up transaction alerts. Contact your bank to flag your account for suspicious activity.");
  if (hasPhone && tips.length < 5)
    tips.push("Phone number is in breach data. Add a SIM-lock PIN with your carrier to prevent SIM-swap attacks that bypass SMS two-factor authentication.");
  if (queryType === "password") {
    tips.push("Never reuse this password anywhere. Generate a new unique password for every account.");
    tips.push("Enable two-factor authentication everywhere. Even a stolen password is useless with 2FA active.");
  }
  if (queryType === "email" && confirmed && tips.length < 5)
    tips.push("Watch your inbox for phishing. Attackers with your email send targeted messages impersonating the breached services. Verify all login prompts manually.");

  const seen = new Set<string>();
  return tips.filter((t) => { if (seen.has(t)) return false; seen.add(t); return true; }).slice(0, 6);
}

// ─── POST /breach/check ───────────────────────────────────────────────────────

router.post("/breach/check", async (req, res): Promise<void> => {
  const parsed = CheckBreachBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }

  const { type, value } = parsed.data;

  try {
    // ── Password ──────────────────────────────────────────────────────────────
    if (type === "password") {
      const result = await checkPasswordHibp(value);
      const score = result.found ? Math.min(50 + Math.log10(result.count + 1) * 15, 100) : 0;
      const tips = buildTips([], result.found ? ["password"] : [], "password", result.found);
      res.json({
        found: result.found,
        query: { type, value: "••••••••" },
        totalBreaches: result.found ? 1 : 0,
        totalPwned: result.count,
        riskScore: Math.round(score),
        riskLevel: riskLevelFromScore(Math.round(score)),
        sources: result.found ? [{
          name: "HibpPasswordDatabase",
          title: "HIBP Pwned Passwords — 14 Billion+ Records",
          date: null, addedDate: null, domain: null,
          dataClasses: ["Passwords"],
          pwnCount: result.count,
          description: `This exact password appeared ${result.count.toLocaleString()} times across known breach databases. Attackers use these lists in credential-stuffing attacks against every major platform.`,
          logoPath: null, isVerified: true, isSensitive: true, riskLevel: "critical",
        }] : [],
        tips,
        summary: result.found
          ? `This exact password appeared in ${result.count.toLocaleString()} breach records across 14+ billion password database. It is fully compromised.`
          : "This password was not found in any of the 14+ billion breach records checked. It currently appears safe.",
      });
      return;
    }

    const catalog = await fetchCatalog();

    // ── Email ─────────────────────────────────────────────────────────────────
    if (type === "email") {
      const emailDomain = value.split("@")[1]?.toLowerCase() ?? "";

      // LeakCheck is the primary source for real per-email data
      const leakCheck = await checkLeakCheck(value);

      let confirmed = false;
      let leakCheckFound = 0;
      let leakCheckFields: string[] = [];
      let leakCheckSources: LeakCheckSource[] = [];

      if (leakCheck?.success && (leakCheck.found ?? 0) > 0) {
        confirmed = true;
        leakCheckFound = leakCheck.found;
        leakCheckFields = leakCheck.fields ?? [];
        leakCheckSources = leakCheck.sources ?? [];
      }

      // Exact domain breaches (email's own service was breached)
      const domainBreaches = catalog.filter(
        (b) => b.Domain && b.Domain.toLowerCase() === emailDomain
      );
      if (domainBreaches.length > 0) confirmed = true;

      // If not confirmed by any source, return clean result
      if (!confirmed) {
        res.json({
          found: false,
          query: { type, value },
          totalBreaches: 0,
          totalPwned: 0,
          riskScore: 0,
          riskLevel: "safe",
          sources: [],
          tips: [
            "Keep your email address private and avoid signing up for services you don't trust.",
            "Enable two-factor authentication on your email account as a precaution.",
          ],
          summary: "No breach data found for this email address in our database. Your email appears to be clean — but new breaches are added daily, so check periodically.",
        });
        return;
      }

      // Match LeakCheck sources to HIBP catalog
      const { matched: hibpMatched, unmatched: lcUnmatched } = matchToCatalog(leakCheckSources, catalog);

      // Add domain breaches to matched list
      for (const db of domainBreaches) {
        if (!hibpMatched.find((b) => b.Name === db.Name)) hibpMatched.push(db);
      }

      // Build stub sources for unmatched LeakCheck entries
      const dataClasses = fieldsToDataClasses(leakCheckFields);
      const stubSources = lcUnmatched.slice(0, 15).map((s) => buildLeakCheckStub(s, dataClasses));

      // All sources: HIBP-enriched first, then stubs
      const allSources = [
        ...hibpMatched.map(buildHibpSource),
        ...stubSources,
      ];

      const score = computeRiskFromLeakCheck(confirmed, leakCheckFound, leakCheckFields, hibpMatched, lcUnmatched.length);
      const tips = buildTips(hibpMatched, leakCheckFields, "email", confirmed);

      const totalPwned = hibpMatched.reduce((s, b) => s + (b.PwnCount ?? 0), 0);
      const totalSources = leakCheckSources.length || hibpMatched.length;

      res.json({
        found: true,
        query: { type, value },
        totalBreaches: allSources.length,
        totalPwned,
        riskScore: score,
        riskLevel: riskLevelFromScore(score),
        sources: allSources,
        tips,
        summary: `Your email was confirmed in ${totalSources} breach source${totalSources !== 1 ? "s" : ""} (${leakCheckFound.toLocaleString()} records found). ${dataClasses.length > 0 ? "Exposed data types: " + dataClasses.slice(0, 4).join(", ") + "." : ""}`,
      });
      return;
    }

    // ── Domain ─────────────────────────────────────────────────────────────────
    if (type === "domain") {
      const domainLower = value.toLowerCase().replace(/^www\./, "");
      const exactMatches = catalog.filter((b) => b.Domain && b.Domain.toLowerCase() === domainLower);

      // Also try LeakCheck for domain
      const leakCheck = await checkLeakCheck(domainLower);
      const lcSources: LeakCheckSource[] = leakCheck?.success && leakCheck.found > 0 ? leakCheck.sources ?? [] : [];
      const { matched: lcMatched } = matchToCatalog(lcSources, catalog);
      const allMatched = [...exactMatches];
      for (const b of lcMatched) if (!allMatched.find((m) => m.Name === b.Name)) allMatched.push(b);

      const confirmed = allMatched.length > 0;
      const score = computeRiskFromLeakCheck(confirmed, leakCheck?.found ?? 0, leakCheck?.fields ?? [], allMatched, 0);
      const tips = buildTips(allMatched, leakCheck?.fields ?? [], "domain", confirmed);
      const totalPwned = allMatched.reduce((s, b) => s + (b.PwnCount ?? 0), 0);

      res.json({
        found: confirmed,
        query: { type, value },
        totalBreaches: allMatched.length,
        totalPwned,
        riskScore: confirmed ? score : 0,
        riskLevel: confirmed ? riskLevelFromScore(score) : "safe",
        sources: allMatched.map(buildHibpSource),
        tips,
        summary: confirmed
          ? `Domain "${value}" was involved in ${allMatched.length} confirmed breach${allMatched.length !== 1 ? "es" : ""}, exposing ~${totalPwned.toLocaleString()} records.`
          : `No known breaches found for domain "${value}". This domain appears clean in public databases.`,
      });
      return;
    }

    // ── Username ───────────────────────────────────────────────────────────────
    if (type === "username") {
      const leakCheck = await checkLeakCheck(value);
      const confirmed = !!(leakCheck?.success && (leakCheck.found ?? 0) > 0);
      const lcSources: LeakCheckSource[] = confirmed ? leakCheck!.sources ?? [] : [];
      const lcFields: string[] = confirmed ? leakCheck!.fields ?? [] : [];
      const { matched, unmatched } = matchToCatalog(lcSources, catalog);
      const dataClasses = fieldsToDataClasses(lcFields);
      const stubs = unmatched.slice(0, 10).map((s) => buildLeakCheckStub(s, dataClasses));
      const allSources = [...matched.map(buildHibpSource), ...stubs];
      const score = computeRiskFromLeakCheck(confirmed, leakCheck?.found ?? 0, lcFields, matched, unmatched.length);
      const tips = buildTips(matched, lcFields, "username", confirmed);
      const totalPwned = matched.reduce((s, b) => s + (b.PwnCount ?? 0), 0);

      res.json({
        found: confirmed,
        query: { type, value },
        totalBreaches: allSources.length,
        totalPwned,
        riskScore: confirmed ? score : 0,
        riskLevel: confirmed ? riskLevelFromScore(score) : "safe",
        sources: allSources,
        tips: confirmed ? tips : ["This username does not appear in known public breach databases. Keep monitoring as new breaches are added regularly."],
        summary: confirmed
          ? `Username "${value}" found in ${(leakCheck!.found ?? 0).toLocaleString()} records across ${lcSources.length || allSources.length} breach source${lcSources.length !== 1 ? "s" : ""}. Exposed: ${dataClasses.slice(0, 3).join(", ") || "account data"}.`
          : `Username "${value}" was not found in any known breach database. It appears clean.`,
      });
      return;
    }

    // ── Phone ──────────────────────────────────────────────────────────────────
    if (type === "phone") {
      const cleanPhone = value.replace(/[\s\-().+]/g, "");
      const leakCheck = await checkLeakCheck(cleanPhone);
      const confirmed = !!(leakCheck?.success && (leakCheck.found ?? 0) > 0);
      const lcSources: LeakCheckSource[] = confirmed ? leakCheck!.sources ?? [] : [];
      const lcFields: string[] = confirmed ? leakCheck!.fields ?? [] : [];
      const { matched, unmatched } = matchToCatalog(lcSources, catalog);
      const dataClasses = fieldsToDataClasses(lcFields);
      const stubs = unmatched.slice(0, 10).map((s) => buildLeakCheckStub(s, dataClasses));
      const allSources = [...matched.map(buildHibpSource), ...stubs];
      const score = computeRiskFromLeakCheck(confirmed, leakCheck?.found ?? 0, lcFields, matched, unmatched.length);
      const tips = buildTips(matched, lcFields, "phone", confirmed);
      const totalPwned = matched.reduce((s, b) => s + (b.PwnCount ?? 0), 0);

      res.json({
        found: confirmed,
        query: { type, value },
        totalBreaches: allSources.length,
        totalPwned,
        riskScore: confirmed ? score : 0,
        riskLevel: confirmed ? riskLevelFromScore(score) : "safe",
        sources: allSources,
        tips: confirmed ? tips : ["This phone number was not found in known breach databases. Add a SIM-lock PIN with your carrier as a precautionary measure."],
        summary: confirmed
          ? `Phone number found in ${(leakCheck!.found ?? 0).toLocaleString()} records across ${lcSources.length || allSources.length} source${lcSources.length !== 1 ? "s" : ""}. Exposed: ${dataClasses.slice(0, 3).join(", ") || "account data"}.`
          : `This phone number was not found in any known breach database. It appears clean.`,
      });
      return;
    }

    // ── IP Address ─────────────────────────────────────────────────────────────
    if (type === "ip") {
      const leakCheck = await checkLeakCheck(value);
      const confirmed = !!(leakCheck?.success && (leakCheck.found ?? 0) > 0);
      const lcSources: LeakCheckSource[] = confirmed ? leakCheck!.sources ?? [] : [];
      const lcFields: string[] = confirmed ? leakCheck!.fields ?? [] : [];
      const { matched, unmatched } = matchToCatalog(lcSources, catalog);
      const dataClasses = fieldsToDataClasses(lcFields);
      const stubs = unmatched.slice(0, 10).map((s) => buildLeakCheckStub(s, dataClasses));
      const allSources = [...matched.map(buildHibpSource), ...stubs];
      const score = computeRiskFromLeakCheck(confirmed, leakCheck?.found ?? 0, lcFields, matched, unmatched.length);
      const tips = buildTips(matched, lcFields, "ip", confirmed);
      const totalPwned = matched.reduce((s, b) => s + (b.PwnCount ?? 0), 0);

      res.json({
        found: confirmed,
        query: { type, value },
        totalBreaches: allSources.length,
        totalPwned,
        riskScore: confirmed ? score : 0,
        riskLevel: confirmed ? riskLevelFromScore(score) : "safe",
        sources: allSources,
        tips: confirmed ? tips : ["This IP address was not found in known breach databases. Use a VPN to reduce IP-based tracking and future exposure."],
        summary: confirmed
          ? `IP address ${value} was found in ${(leakCheck!.found ?? 0).toLocaleString()} records. Exposed: ${dataClasses.slice(0, 3).join(", ") || "network data"}.`
          : `IP address ${value} was not found in any known breach database. It appears clean.`,
      });
      return;
    }

    res.status(400).json({ error: "Unsupported query type" });
  } catch (err) {
    console.error("Breach check failed:", err);
    res.status(500).json({ error: "Failed to check breach data. Please try again." });
  }
});

// ─── GET /breach/catalog ──────────────────────────────────────────────────────

router.get("/breach/catalog", async (req, res): Promise<void> => {
  try {
    const catalog = await fetchCatalog();
    res.json(catalog.map((b) => ({
      name: b.Name, title: b.Title, domain: b.Domain,
      breachDate: b.BreachDate, addedDate: b.AddedDate,
      pwnCount: b.PwnCount, description: b.Description,
      logoPath: b.LogoPath, dataClasses: b.DataClasses,
      isVerified: b.IsVerified, isFabricated: b.IsFabricated,
      isSensitive: b.IsSensitive, isRetired: b.IsRetired, isSpamList: b.IsSpamList,
    })));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch breach catalog" });
  }
});

// ─── GET /breach/stats ────────────────────────────────────────────────────────

router.get("/breach/stats", async (req, res): Promise<void> => {
  try {
    const catalog = await fetchCatalog();
    const totalPwned = catalog.reduce((s, b) => s + (b.PwnCount ?? 0), 0);
    const largest = catalog.reduce((max, b) => b.PwnCount > (max?.PwnCount ?? 0) ? b : max, catalog[0]);
    const newest = catalog.filter((b) => b.BreachDate)
      .sort((a, b) => new Date(b.BreachDate).getTime() - new Date(a.BreachDate).getTime())[0];
    const dcCount: Record<string, number> = {};
    for (const breach of catalog) for (const dc of breach.DataClasses) dcCount[dc] = (dcCount[dc] ?? 0) + 1;
    res.json({
      totalBreaches: catalog.length,
      totalPwnedAccounts: totalPwned,
      totalDataClasses: new Set(catalog.flatMap((b) => b.DataClasses)).size,
      largestBreach: { name: largest?.Name ?? "", pwnCount: largest?.PwnCount ?? 0 },
      newestBreach: { name: newest?.Name ?? "", date: newest?.BreachDate ?? "" },
      mostCommonDataTypes: Object.entries(dcCount).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([type, count]) => ({ type, count })),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch breach stats" });
  }
});

export default router;
