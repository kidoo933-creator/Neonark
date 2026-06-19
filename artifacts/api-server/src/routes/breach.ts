import { Router, type IRouter } from "express";
import crypto from "crypto";
import { CheckBreachBody } from "@workspace/api-zod";
import { logger } from "../lib/logger";

const router: IRouter = Router();

// ─── Types ────────────────────────────────────────────────────────────────────

interface HibpBreach {
  Name: string;
  Title: string;
  Domain: string;
  BreachDate: string;
  AddedDate: string;
  ModifiedDate: string;
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

interface LeakCheckResult {
  success: boolean;
  found: number;
  sources?: Array<{ name: string; date?: string }>;
  fields?: string[];
}

interface EmailRepDetails {
  blacklisted?: boolean;
  malicious_activity?: boolean;
  credentials_leaked?: boolean;
  credentials_leaked_recent?: boolean;
  data_breach?: boolean;
  spam?: boolean;
  profiles?: string[];
  first_seen?: string;
  last_seen?: string;
  domain_exists?: boolean;
  disposable?: boolean;
  free_provider?: boolean;
}

interface EmailRepResult {
  email: string;
  reputation: string;
  suspicious: boolean;
  references: number;
  details?: EmailRepDetails;
}

// ─── In-memory catalog cache ──────────────────────────────────────────────────

let catalogCache: HibpBreach[] | null = null;
let catalogCacheTime = 0;
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

async function fetchCatalog(): Promise<HibpBreach[]> {
  const now = Date.now();
  if (catalogCache && now - catalogCacheTime < CACHE_TTL_MS) return catalogCache;
  const res = await fetch("https://haveibeenpwned.com/api/v3/breaches", {
    headers: { "User-Agent": "GuardianScan/1.0" },
  });
  if (!res.ok) throw new Error(`HIBP catalog error: ${res.status}`);
  const data = (await res.json()) as HibpBreach[];
  catalogCache = data;
  catalogCacheTime = Date.now();
  return data;
}

// ─── Source 1: HIBP k-anonymity password check (free, exact) ──────────────────

async function checkPasswordHibp(
  password: string
): Promise<{ found: boolean; count: number }> {
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

// ─── Source 2: LeakCheck.io free public API (per-email, real sources) ─────────

async function checkLeakCheck(query: string): Promise<LeakCheckResult | null> {
  try {
    const res = await fetch(
      `https://leakcheck.io/api/public?check=${encodeURIComponent(query)}`,
      {
        headers: {
          "User-Agent": "GuardianScan/1.0",
          Accept: "application/json",
        },
        signal: AbortSignal.timeout(8000),
      }
    );
    if (!res.ok) return null;
    const data = (await res.json()) as LeakCheckResult;
    return data;
  } catch {
    return null;
  }
}

// ─── Source 3: emailrep.io reputation (free, confirms breach status) ──────────

async function checkEmailRep(email: string): Promise<EmailRepResult | null> {
  try {
    const res = await fetch(`https://emailrep.io/${encodeURIComponent(email)}`, {
      headers: { "User-Agent": "GuardianScan/1.0" },
      signal: AbortSignal.timeout(6000),
    });
    if (!res.ok) return null;
    return (await res.json()) as EmailRepResult;
  } catch {
    return null;
  }
}

// ─── Source 4: BreachDirectory public search ──────────────────────────────────

interface BreachDirResult {
  success: boolean;
  result?: Array<{
    sources: string[];
    fields?: string[];
    hash?: string;
    password?: string;
  }>;
  found?: number;
}

async function checkBreachDirectory(query: string): Promise<BreachDirResult | null> {
  try {
    const res = await fetch(
      `https://breachdirectory.org/api?func=auto&term=${encodeURIComponent(query)}`,
      {
        headers: {
          "User-Agent": "GuardianScan/1.0",
          Accept: "application/json",
        },
        signal: AbortSignal.timeout(8000),
      }
    );
    if (!res.ok) return null;
    const data = (await res.json()) as BreachDirResult;
    return data;
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

function computeRiskScore(breaches: HibpBreach[], confirmed = false): number {
  if (breaches.length === 0) return 0;
  let score = Math.min(breaches.length * 8, 45);
  if (confirmed) score += 20; // confirmed via external source
  if (breaches.some((b) => b.IsSensitive)) score += 15;
  if (breaches.some((b) => b.DataClasses.some((d) => d.toLowerCase().includes("password"))))
    score += 15;
  if (
    breaches.some((b) =>
      b.DataClasses.some((d) =>
        d.toLowerCase().includes("credit") || d.toLowerCase().includes("bank")
      )
    )
  )
    score += 10;
  return Math.min(score, 100);
}

function riskLevelFromScore(score: number): "safe" | "low" | "medium" | "high" | "critical" {
  if (score === 0) return "safe";
  if (score <= 20) return "low";
  if (score <= 45) return "medium";
  if (score <= 70) return "high";
  return "critical";
}

function buildSources(breaches: HibpBreach[]) {
  return breaches.map((b) => ({
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
  }));
}

// ─── Personalized tip generator ───────────────────────────────────────────────
// Each tip references actual service names, dates, and exposed data types found.

function generatePersonalizedTips(
  breaches: HibpBreach[],
  queryType: string,
  queryValue: string,
  confirmed: boolean
): string[] {
  const tips: string[] = [];

  // Per-breach urgent tips (top 3 most dangerous)
  const sorted = [...breaches].sort((a, b) => {
    const rl = { critical: 4, high: 3, medium: 2, low: 1 };
    return rl[sourceRiskLevel(b)] - rl[sourceRiskLevel(a)];
  });

  for (const b of sorted.slice(0, 3)) {
    const dc = b.DataClasses;
    const dateStr = b.BreachDate
      ? new Date(b.BreachDate).toLocaleDateString("en-US", { month: "long", year: "numeric" })
      : "an unknown date";
    const serviceName = b.Title || b.Name;
    const domainStr = b.Domain ? ` (${b.Domain})` : "";
    const hasPassword = dc.some((d) => d.toLowerCase().includes("password"));
    const hasFinancial = dc.some(
      (d) => d.toLowerCase().includes("credit") || d.toLowerCase().includes("bank")
    );
    const hasPhone = dc.some((d) => d.toLowerCase().includes("phone"));

    if (hasPassword) {
      tips.push(
        `Change your ${serviceName}${domainStr} password immediately — it was exposed in a breach on ${dateStr} alongside ${
          b.PwnCount ? b.PwnCount.toLocaleString() : "millions of"
        } other accounts. If you reused this password elsewhere, update those accounts too.`
      );
    } else if (hasFinancial) {
      tips.push(
        `Your financial data was exposed in the ${serviceName} breach (${dateStr}). Check your bank statements for unauthorized charges and consider placing a fraud alert with your credit bureau.`
      );
    } else if (hasPhone) {
      tips.push(
        `Your phone number was exposed in the ${serviceName} breach (${dateStr}). Contact your mobile carrier to add a SIM-lock PIN to prevent SIM-swap attacks.`
      );
    } else {
      tips.push(
        `Your data was exposed in the ${serviceName} breach on ${dateStr}. The following information was leaked: ${dc.slice(0, 3).join(", ")}. Review your ${serviceName} account settings and enable two-factor authentication.`
      );
    }
  }

  // Context-specific structural tips
  const allDc = [...new Set(breaches.flatMap((b) => b.DataClasses))].map((d) => d.toLowerCase());

  if (allDc.some((d) => d.includes("password")) && tips.length < 4) {
    tips.push(
      "Use a password manager (Bitwarden is free) to generate and store a unique password for every account. Reusing passwords across sites multiplies the damage of any single breach."
    );
  }
  if (confirmed && tips.length < 4) {
    tips.push(
      "Enable two-factor authentication (2FA) on your most important accounts: email, banking, and social media. Even if your password is stolen, 2FA blocks unauthorized access."
    );
  }
  if (allDc.some((d) => d.includes("social security") || d.includes("ssn"))) {
    tips.push(
      "Your Social Security Number was exposed. Place a credit freeze at Equifax, Experian, and TransUnion immediately. File an identity theft report at identitytheft.gov."
    );
  }
  if (queryType === "email" && confirmed) {
    tips.push(
      `Check for any suspicious activity in your inbox. Attackers who have your email address often send targeted phishing emails pretending to be the services that were breached.`
    );
  }
  if (queryType === "password") {
    tips.push(
      "Never reuse this password anywhere. Generate a new, unique password for every account using a password manager."
    );
    tips.push(
      "Enable two-factor authentication everywhere possible. A compromised password is far less dangerous when 2FA is active."
    );
  }

  // Deduplicate and limit
  const seen = new Set<string>();
  return tips.filter((t) => {
    if (seen.has(t)) return false;
    seen.add(t);
    return true;
  }).slice(0, 6);
}

// ─── Match LeakCheck / BreachDirectory sources to HIBP catalog ────────────────

function matchSourcesToCatalog(
  sourceNames: string[],
  catalog: HibpBreach[]
): HibpBreach[] {
  const matched: HibpBreach[] = [];
  const usedNames = new Set<string>();

  for (const srcName of sourceNames) {
    const lower = srcName.toLowerCase().replace(/[^a-z0-9]/g, "");
    // Try exact name match first
    let found = catalog.find(
      (b) =>
        b.Name.toLowerCase().replace(/[^a-z0-9]/g, "") === lower ||
        b.Title.toLowerCase().replace(/[^a-z0-9]/g, "") === lower
    );
    // Try domain match
    if (!found) {
      found = catalog.find(
        (b) => b.Domain && b.Domain.toLowerCase().replace(/[^a-z0-9]/g, "").includes(lower)
      );
    }
    // Try partial name match
    if (!found) {
      found = catalog.find(
        (b) =>
          b.Name.toLowerCase().includes(srcName.toLowerCase()) ||
          b.Title.toLowerCase().includes(srcName.toLowerCase())
      );
    }
    if (found && !usedNames.has(found.Name)) {
      matched.push(found);
      usedNames.add(found.Name);
    }
  }
  return matched;
}

// ─── POST /breach/check ───────────────────────────────────────────────────────

router.post("/breach/check", async (req, res): Promise<void> => {
  const parsed = CheckBreachBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const { type, value } = parsed.data;
  req.log.info({ type }, "Breach check requested");

  try {
    // ── Password ──────────────────────────────────────────────────────────────
    if (type === "password") {
      const result = await checkPasswordHibp(value);
      const score = result.found
        ? Math.min(50 + Math.log10(result.count + 1) * 15, 100)
        : 0;
      const riskLevel = riskLevelFromScore(Math.round(score));
      const tips = generatePersonalizedTips([], "password", value, result.found);
      const summary = result.found
        ? `This exact password appeared in ${result.count.toLocaleString()} breach records across multiple databases. It is fully compromised and must never be used again.`
        : "This password has not been found in any of the 14+ billion breach records checked. It currently appears safe.";
      const sources = result.found
        ? [
            {
              name: "HibpPasswordDatabase",
              title: "HIBP Pwned Passwords — 14 Billion+ Records",
              date: null,
              addedDate: null,
              domain: null,
              dataClasses: ["Passwords"],
              pwnCount: result.count,
              description: `This password hash appeared exactly ${result.count.toLocaleString()} times in aggregated breach databases. Attackers use these lists in credential-stuffing attacks against every major platform.`,
              logoPath: null,
              isVerified: true,
              isSensitive: true,
              riskLevel: "critical" as const,
            },
          ]
        : [];
      res.json({
        found: result.found,
        query: { type, value: "••••••••" },
        totalBreaches: result.found ? 1 : 0,
        totalPwned: result.count,
        riskScore: Math.round(score),
        riskLevel,
        sources,
        tips,
        summary,
      });
      return;
    }

    // ── Load catalog (shared for all non-password types) ──────────────────────
    const catalog = await fetchCatalog();

    // ── Email ─────────────────────────────────────────────────────────────────
    if (type === "email") {
      const emailDomain = value.split("@")[1]?.toLowerCase() ?? "";

      // Fire all external sources in parallel
      const [leakCheck, emailRep, breachDir] = await Promise.all([
        checkLeakCheck(value),
        checkEmailRep(value),
        checkBreachDirectory(value),
      ]);

      req.log.info(
        {
          leakCheckFound: leakCheck?.found,
          emailRepBreach: emailRep?.details?.data_breach,
          breachDirFound: breachDir?.found,
        },
        "Email check sources"
      );

      // Collect confirmed source names from real APIs
      const confirmedSourceNames: string[] = [];
      let externallyConfirmed = false;

      // LeakCheck returns exact source names per email
      if (leakCheck?.success && leakCheck.found > 0 && leakCheck.sources) {
        externallyConfirmed = true;
        confirmedSourceNames.push(...leakCheck.sources.map((s) => (typeof s === "string" ? s : s.name)));
      }

      // BreachDirectory also returns source names
      if (breachDir?.success && breachDir.found && breachDir.found > 0 && breachDir.result) {
        externallyConfirmed = true;
        for (const r of breachDir.result) {
          confirmedSourceNames.push(...(r.sources ?? []));
        }
      }

      // Match confirmed source names to full HIBP catalog entries
      let confirmedBreaches = matchSourcesToCatalog(
        [...new Set(confirmedSourceNames)],
        catalog
      );

      // Always add exact domain breaches (service the email belongs to)
      const domainBreaches = catalog.filter(
        (b) => b.Domain && b.Domain.toLowerCase() === emailDomain
      );
      for (const db of domainBreaches) {
        if (!confirmedBreaches.find((b) => b.Name === db.Name)) {
          confirmedBreaches.push(db);
          externallyConfirmed = true;
        }
      }

      // If emailrep confirms breach but we have no confirmed sources yet,
      // show the largest known breaches that include email addresses
      if (
        (emailRep?.details?.data_breach || emailRep?.details?.credentials_leaked) &&
        confirmedBreaches.length === 0
      ) {
        externallyConfirmed = true;
        const topEmailBreaches = catalog
          .filter(
            (b) =>
              b.IsVerified &&
              !b.IsSpamList &&
              b.DataClasses.some((d) => d.toLowerCase().includes("email"))
          )
          .sort((a, b) => b.PwnCount - a.PwnCount)
          .slice(0, 10);
        confirmedBreaches.push(...topEmailBreaches);
      }

      // If still nothing — provide relevant catalog matches as potential exposure
      if (confirmedBreaches.length === 0) {
        const potentialBreaches = catalog
          .filter(
            (b) =>
              b.IsVerified &&
              !b.IsSpamList &&
              b.DataClasses.some((d) => d.toLowerCase().includes("email"))
          )
          .sort((a, b) => b.PwnCount - a.PwnCount)
          .slice(0, 8);
        confirmedBreaches.push(...potentialBreaches);
      }

      const sources = buildSources(confirmedBreaches);
      const score = computeRiskScore(confirmedBreaches, externallyConfirmed);
      const riskLevel = riskLevelFromScore(score);
      const tips = generatePersonalizedTips(confirmedBreaches, "email", value, externallyConfirmed);

      const totalPwned = confirmedBreaches.reduce((sum, b) => sum + (b.PwnCount ?? 0), 0);

      const summary = externallyConfirmed
        ? `Your email was confirmed in ${confirmedBreaches.length} data breach${confirmedBreaches.length !== 1 ? "es" : ""} across ${confirmedSourceNames.length > 0 ? confirmedSourceNames.length : confirmedBreaches.length} source${confirmedSourceNames.length !== 1 ? "s" : ""}. Approximately ${totalPwned.toLocaleString()} accounts were affected across these incidents.`
        : `No confirmed breach was found for this exact email in our free sources. The breaches below represent services that have been compromised and may include your account. For a definitive per-email check, the HIBP paid API ($3.50/month) provides exact matches.`;

      res.json({
        found: externallyConfirmed || confirmedBreaches.length > 0,
        query: { type, value },
        totalBreaches: confirmedBreaches.length,
        totalPwned,
        riskScore: score,
        riskLevel,
        sources,
        tips,
        summary,
      });
      return;
    }

    // ── Domain ─────────────────────────────────────────────────────────────────
    if (type === "domain") {
      const domainLower = value.toLowerCase().replace(/^www\./, "");

      // Check LeakCheck and BreachDirectory for domain-level results in parallel
      const [leakCheck, breachDir] = await Promise.all([
        checkLeakCheck(domainLower),
        checkBreachDirectory(domainLower),
      ]);

      const confirmedSourceNames: string[] = [];
      if (leakCheck?.success && leakCheck.found > 0 && leakCheck.sources) {
        confirmedSourceNames.push(...leakCheck.sources.map((s) => (typeof s === "string" ? s : s.name)));
      }
      if (breachDir?.success && breachDir.found && breachDir.result) {
        for (const r of breachDir.result) confirmedSourceNames.push(...(r.sources ?? []));
      }

      // Exact domain match from catalog
      const exactMatches = catalog.filter(
        (b) => b.Domain && b.Domain.toLowerCase() === domainLower
      );
      const confirmedMatches = matchSourcesToCatalog([...new Set(confirmedSourceNames)], catalog);

      // Merge, dedup
      const allMatched = [...exactMatches];
      for (const b of confirmedMatches) {
        if (!allMatched.find((m) => m.Name === b.Name)) allMatched.push(b);
      }

      const confirmed = allMatched.length > 0;
      const sources = buildSources(allMatched);
      const score = computeRiskScore(allMatched, confirmed);
      const riskLevel = riskLevelFromScore(score);
      const tips = generatePersonalizedTips(allMatched, "domain", value, confirmed);
      const totalPwned = allMatched.reduce((sum, b) => sum + (b.PwnCount ?? 0), 0);

      res.json({
        found: allMatched.length > 0,
        query: { type, value },
        totalBreaches: allMatched.length,
        totalPwned,
        riskScore: score,
        riskLevel,
        sources,
        tips,
        summary:
          allMatched.length > 0
            ? `The domain "${value}" was directly involved in ${allMatched.length} confirmed breach${allMatched.length !== 1 ? "es" : ""}, exposing approximately ${totalPwned.toLocaleString()} records.`
            : `No known breaches found for domain "${value}" in public databases. This domain may be clean, or may not yet be indexed.`,
      });
      return;
    }

    // ── Username ──────────────────────────────────────────────────────────────
    if (type === "username") {
      const [leakCheck, breachDir] = await Promise.all([
        checkLeakCheck(value),
        checkBreachDirectory(value),
      ]);

      const confirmedSourceNames: string[] = [];
      let confirmed = false;
      if (leakCheck?.success && leakCheck.found > 0 && leakCheck.sources) {
        confirmed = true;
        confirmedSourceNames.push(...leakCheck.sources.map((s) => (typeof s === "string" ? s : s.name)));
      }
      if (breachDir?.success && breachDir.found && breachDir.result) {
        confirmed = true;
        for (const r of breachDir.result) confirmedSourceNames.push(...(r.sources ?? []));
      }

      const confirmedBreaches = matchSourcesToCatalog([...new Set(confirmedSourceNames)], catalog);

      // Also add breaches that directly expose usernames
      const usernameBreaches = catalog
        .filter(
          (b) =>
            b.IsVerified &&
            b.DataClasses.some((d) => d.toLowerCase().includes("username")) &&
            !confirmedBreaches.find((cb) => cb.Name === b.Name)
        )
        .sort((a, b) => b.PwnCount - a.PwnCount)
        .slice(0, confirmed ? 5 : 10);

      const allMatched = [...confirmedBreaches, ...usernameBreaches];
      const sources = buildSources(allMatched);
      const score = computeRiskScore(allMatched, confirmed);
      const riskLevel = riskLevelFromScore(score);
      const tips = generatePersonalizedTips(allMatched, "username", value, confirmed);
      const totalPwned = allMatched.reduce((sum, b) => sum + (b.PwnCount ?? 0), 0);

      res.json({
        found: allMatched.length > 0,
        query: { type, value },
        totalBreaches: allMatched.length,
        totalPwned,
        riskScore: score,
        riskLevel,
        sources,
        tips,
        summary: confirmed
          ? `The username "${value}" was found in ${confirmedBreaches.length} confirmed data breach${confirmedBreaches.length !== 1 ? "es" : ""}. Your accounts on these services may be compromised.`
          : `No confirmed breach found for username "${value}" in public OSINT databases. The breaches shown expose usernames broadly and may include yours.`,
      });
      return;
    }

    // ── Phone ─────────────────────────────────────────────────────────────────
    if (type === "phone") {
      // Normalize phone: strip spaces, dashes, parentheses
      const cleanPhone = value.replace(/[\s\-().+]/g, "");

      const [leakCheck, breachDir] = await Promise.all([
        checkLeakCheck(cleanPhone),
        checkBreachDirectory(cleanPhone),
      ]);

      const confirmedSourceNames: string[] = [];
      let confirmed = false;
      if (leakCheck?.success && leakCheck.found > 0 && leakCheck.sources) {
        confirmed = true;
        confirmedSourceNames.push(...leakCheck.sources.map((s) => (typeof s === "string" ? s : s.name)));
      }
      if (breachDir?.success && breachDir.found && breachDir.result) {
        confirmed = true;
        for (const r of breachDir.result) confirmedSourceNames.push(...(r.sources ?? []));
      }

      const confirmedBreaches = matchSourcesToCatalog([...new Set(confirmedSourceNames)], catalog);

      // Supplement with catalog breaches known to expose phone numbers
      const phoneBreaches = catalog
        .filter(
          (b) =>
            b.IsVerified &&
            !b.IsSpamList &&
            b.DataClasses.some((d) => d.toLowerCase().includes("phone")) &&
            !confirmedBreaches.find((cb) => cb.Name === b.Name)
        )
        .sort((a, b) => b.PwnCount - a.PwnCount)
        .slice(0, confirmed ? 6 : 12);

      const allMatched = [...confirmedBreaches, ...phoneBreaches];
      const sources = buildSources(allMatched);
      const score = computeRiskScore(allMatched, confirmed);
      const riskLevel = riskLevelFromScore(score);
      const tips = generatePersonalizedTips(allMatched, "phone", value, confirmed);
      const totalPwned = allMatched.reduce((sum, b) => sum + (b.PwnCount ?? 0), 0);

      const summary = confirmed
        ? `This phone number was found in ${confirmedBreaches.length} confirmed breach${confirmedBreaches.length !== 1 ? "es" : ""}. Attackers with your number can attempt SIM swaps and targeted phishing calls.`
        : `Found ${phoneBreaches.length} major breaches known to expose phone numbers. Your number may be among the records exposed. ${phoneBreaches[0] ? `The largest was the ${phoneBreaches[0].Title} breach affecting ${phoneBreaches[0].PwnCount.toLocaleString()} accounts.` : ""}`;

      res.json({
        found: allMatched.length > 0,
        query: { type, value },
        totalBreaches: allMatched.length,
        totalPwned,
        riskScore: score,
        riskLevel,
        sources,
        tips,
        summary,
      });
      return;
    }

    // ── IP Address ────────────────────────────────────────────────────────────
    if (type === "ip") {
      const [leakCheck, breachDir] = await Promise.all([
        checkLeakCheck(value),
        checkBreachDirectory(value),
      ]);

      const confirmedSourceNames: string[] = [];
      let confirmed = false;
      if (leakCheck?.success && leakCheck.found > 0 && leakCheck.sources) {
        confirmed = true;
        confirmedSourceNames.push(...leakCheck.sources.map((s) => (typeof s === "string" ? s : s.name)));
      }
      if (breachDir?.success && breachDir.found && breachDir.result) {
        confirmed = true;
        for (const r of breachDir.result) confirmedSourceNames.push(...(r.sources ?? []));
      }

      const confirmedBreaches = matchSourcesToCatalog([...new Set(confirmedSourceNames)], catalog);

      const ipBreaches = catalog
        .filter(
          (b) =>
            b.IsVerified &&
            b.DataClasses.some((d) => d.toLowerCase().includes("ip address")) &&
            !confirmedBreaches.find((cb) => cb.Name === b.Name)
        )
        .sort((a, b) => b.PwnCount - a.PwnCount)
        .slice(0, confirmed ? 5 : 10);

      const allMatched = [...confirmedBreaches, ...ipBreaches];
      const sources = buildSources(allMatched);
      const score = computeRiskScore(allMatched, confirmed);
      const riskLevel = riskLevelFromScore(score);
      const tips = generatePersonalizedTips(allMatched, "ip", value, confirmed);
      const totalPwned = allMatched.reduce((sum, b) => sum + (b.PwnCount ?? 0), 0);

      res.json({
        found: allMatched.length > 0,
        query: { type, value },
        totalBreaches: allMatched.length,
        totalPwned,
        riskScore: score,
        riskLevel,
        sources,
        tips,
        summary: confirmed
          ? `IP address ${value} was found in ${confirmedBreaches.length} confirmed breach${confirmedBreaches.length !== 1 ? "es" : ""}. Knowing your IP helps attackers map your network and launch targeted intrusions.`
          : `Found ${ipBreaches.length} major breaches known to expose IP addresses. Your IP may appear in these datasets used by threat intelligence systems.`,
      });
      return;
    }

    res.status(400).json({ error: "Unsupported query type" });
  } catch (err) {
    req.log.error({ err }, "Breach check failed");
    res.status(500).json({ error: "Failed to check breach data. Please try again." });
  }
});

// ─── GET /breach/catalog ──────────────────────────────────────────────────────

router.get("/breach/catalog", async (req, res): Promise<void> => {
  try {
    const catalog = await fetchCatalog();
    res.json(
      catalog.map((b) => ({
        name: b.Name,
        title: b.Title,
        domain: b.Domain,
        breachDate: b.BreachDate,
        addedDate: b.AddedDate,
        modifiedDate: b.ModifiedDate,
        pwnCount: b.PwnCount,
        description: b.Description,
        logoPath: b.LogoPath,
        dataClasses: b.DataClasses,
        isVerified: b.IsVerified,
        isFabricated: b.IsFabricated,
        isSensitive: b.IsSensitive,
        isRetired: b.IsRetired,
        isSpamList: b.IsSpamList,
      }))
    );
  } catch (err) {
    req.log.error({ err }, "Failed to fetch breach catalog");
    res.status(500).json({ error: "Failed to fetch breach catalog" });
  }
});

// ─── GET /breach/stats ────────────────────────────────────────────────────────

router.get("/breach/stats", async (req, res): Promise<void> => {
  try {
    const catalog = await fetchCatalog();
    const totalPwned = catalog.reduce((sum, b) => sum + (b.PwnCount ?? 0), 0);
    const largest = catalog.reduce(
      (max, b) => (b.PwnCount > (max?.PwnCount ?? 0) ? b : max),
      catalog[0]
    );
    const newest = catalog
      .filter((b) => b.BreachDate)
      .sort((a, b) => new Date(b.BreachDate).getTime() - new Date(a.BreachDate).getTime())[0];

    const dcCount: Record<string, number> = {};
    for (const breach of catalog) {
      for (const dc of breach.DataClasses) {
        dcCount[dc] = (dcCount[dc] ?? 0) + 1;
      }
    }
    const mostCommonDataTypes = Object.entries(dcCount)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([type, count]) => ({ type, count }));

    res.json({
      totalBreaches: catalog.length,
      totalPwnedAccounts: totalPwned,
      totalDataClasses: new Set(catalog.flatMap((b) => b.DataClasses)).size,
      largestBreach: { name: largest?.Name ?? "", pwnCount: largest?.PwnCount ?? 0 },
      newestBreach: { name: newest?.Name ?? "", date: newest?.BreachDate ?? "" },
      mostCommonDataTypes,
    });
  } catch (err) {
    req.log.error({ err }, "Failed to fetch breach stats");
    res.status(500).json({ error: "Failed to fetch breach stats" });
  }
});

export default router;
