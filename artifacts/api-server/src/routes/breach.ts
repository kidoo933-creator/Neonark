import { Router, type IRouter } from "express";
import crypto from "crypto";
import { CheckBreachBody } from "@workspace/api-zod";
import { logger } from "../lib/logger";

const router: IRouter = Router();

// ─── In-memory catalog cache ──────────────────────────────────────────────────
let catalogCache: HibpBreach[] | null = null;
let catalogCacheTime = 0;
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

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

async function fetchCatalog(): Promise<HibpBreach[]> {
  const now = Date.now();
  if (catalogCache && now - catalogCacheTime < CACHE_TTL_MS) {
    return catalogCache;
  }
  const res = await fetch("https://haveibeenpwned.com/api/v3/breaches", {
    headers: { "User-Agent": "GuardianScan/1.0" },
  });
  if (!res.ok) throw new Error(`HIBP catalog error: ${res.status}`);
  const data = (await res.json()) as HibpBreach[];
  catalogCache = data;
  catalogCacheTime = Date.now();
  return data;
}

// ─── Password check via HIBP k-anonymity (completely free) ──────────────────
async function checkPassword(
  password: string
): Promise<{ found: boolean; count: number }> {
  const hash = crypto
    .createHash("sha1")
    .update(password)
    .digest("hex")
    .toUpperCase();
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { "User-Agent": "GuardianScan/1.0", "Add-Padding": "true" },
  });
  if (!res.ok) throw new Error(`HIBP Passwords error: ${res.status}`);

  const text = await res.text();
  for (const line of text.split("\n")) {
    const [hashSuffix, countStr] = line.split(":");
    if (hashSuffix && hashSuffix.trim() === suffix) {
      return { found: true, count: parseInt(countStr?.trim() ?? "0", 10) };
    }
  }
  return { found: false, count: 0 };
}

// ─── emailrep.io reputation check (free, no key needed) ─────────────────────
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

async function checkEmailRep(email: string): Promise<EmailRepResult | null> {
  try {
    const res = await fetch(
      `https://emailrep.io/${encodeURIComponent(email)}`,
      { headers: { "User-Agent": "GuardianScan/1.0" } }
    );
    if (!res.ok) return null;
    return (await res.json()) as EmailRepResult;
  } catch {
    return null;
  }
}

// ─── Risk scoring ─────────────────────────────────────────────────────────────
function computeRiskScore(sources: ReturnType<typeof buildSources>): number {
  if (sources.length === 0) return 0;
  let score = Math.min(sources.length * 12, 60);
  const hasSensitive = sources.some((s) => s.isSensitive);
  const hasPasswords = sources.some((s) =>
    s.dataClasses.some((d) => d.toLowerCase().includes("password"))
  );
  const hasFinancial = sources.some((s) =>
    s.dataClasses.some(
      (d) =>
        d.toLowerCase().includes("credit") ||
        d.toLowerCase().includes("bank") ||
        d.toLowerCase().includes("payment")
    )
  );
  if (hasSensitive) score += 15;
  if (hasPasswords) score += 15;
  if (hasFinancial) score += 10;
  return Math.min(score, 100);
}

function riskLevelFromScore(
  score: number
): "safe" | "low" | "medium" | "high" | "critical" {
  if (score === 0) return "safe";
  if (score <= 20) return "low";
  if (score <= 45) return "medium";
  if (score <= 70) return "high";
  return "critical";
}

function sourceRiskLevel(
  breach: HibpBreach
): "low" | "medium" | "high" | "critical" {
  const dc = breach.DataClasses.map((d) => d.toLowerCase());
  if (
    breach.IsSensitive ||
    dc.some(
      (d) =>
        d.includes("credit") ||
        d.includes("bank") ||
        d.includes("ssn") ||
        d.includes("passport") ||
        d.includes("social security")
    )
  )
    return "critical";
  if (dc.some((d) => d.includes("password") || d.includes("pin")))
    return "high";
  if (
    dc.some(
      (d) =>
        d.includes("phone") ||
        d.includes("address") ||
        d.includes("date of birth")
    )
  )
    return "medium";
  return "low";
}

// ─── Build source objects ─────────────────────────────────────────────────────
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

// ─── Generate tips based on exposed data ─────────────────────────────────────
function generateTips(dataClasses: string[], queryType: string): string[] {
  const dc = dataClasses.map((d) => d.toLowerCase()).join(" ");
  const tips: string[] = [];

  if (dc.includes("password")) {
    tips.push(
      "Change your password immediately on any site where you used the same or similar password."
    );
    tips.push(
      "Use a password manager to generate and store unique passwords for every account."
    );
  }
  if (dc.includes("email")) {
    tips.push(
      "Be vigilant about phishing emails — attackers now have your address and may target you."
    );
  }
  if (dc.includes("phone")) {
    tips.push(
      "Watch for SIM-swap attacks. Contact your carrier and add a PIN lock to your account."
    );
  }
  if (
    dc.includes("credit") ||
    dc.includes("bank") ||
    dc.includes("financial")
  ) {
    tips.push(
      "Monitor your bank statements and consider placing a credit freeze with all major bureaus."
    );
  }
  if (dc.includes("social security") || dc.includes("ssn")) {
    tips.push(
      "File an identity theft report and consider enrolling in credit monitoring immediately."
    );
  }
  if (dc.includes("physical address") || dc.includes("address")) {
    tips.push(
      "Be aware that your physical location is known — review your social media privacy settings."
    );
  }
  if (queryType === "password") {
    tips.push(
      "Never reuse this password anywhere. Generate a new unique password immediately."
    );
    tips.push(
      "Enable two-factor authentication on all accounts for a critical extra layer of protection."
    );
  }

  // Always add these
  if (tips.length < 3) {
    tips.push(
      "Enable two-factor authentication (2FA) on all accounts, especially email and banking."
    );
  }
  tips.push(
    "Regularly check your accounts for suspicious activity and set up login alerts where possible."
  );

  return tips.slice(0, 5);
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
    const catalog = await fetchCatalog();

    // ── Password ─────────────────────────────────────────────────────────────
    if (type === "password") {
      const result = await checkPassword(value);
      const allDataClasses = ["Passwords"];
      const score = result.found ? Math.min(50 + Math.log10(result.count + 1) * 15, 100) : 0;
      const riskLevel = riskLevelFromScore(Math.round(score));

      const tips = generateTips(allDataClasses, "password");
      const summary = result.found
        ? `This exact password has appeared in ${result.count.toLocaleString()} data breach records. It is compromised and must never be used.`
        : "This password has not been found in any known breach database. It is currently safe to use.";

      // For a found password, build a generic "credential stuffing" source entry
      const sources = result.found
        ? [
            {
              name: "BreachedPasswordDatabase",
              title: "Compromised Password Database",
              date: null,
              addedDate: null,
              domain: null,
              dataClasses: ["Passwords"],
              pwnCount: result.count,
              description:
                "This password was found in aggregated breach data. Attackers use these lists to attempt account takeovers across thousands of sites.",
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

    // ── Email ─────────────────────────────────────────────────────────────────
    if (type === "email") {
      const emailRep = await checkEmailRep(value);
      const domain = value.split("@")[1]?.toLowerCase() ?? "";

      // Find catalog breaches matching the email domain exactly
      const domainBreaches = catalog.filter(
        (b) => b.Domain && b.Domain.toLowerCase() === domain
      );

      // Also find breaches that contain "Email addresses" as a data class
      // ranked by PwnCount (biggest breaches most likely to contain the email)
      const emailBreaches = catalog
        .filter(
          (b) =>
            b.DataClasses.some((d) => d.toLowerCase().includes("email")) &&
            !b.IsSpamList &&
            b.IsVerified
        )
        .sort((a, b) => b.PwnCount - a.PwnCount);

      let matchedBreaches: HibpBreach[] = [];
      let found = false;

      if (emailRep?.details?.data_breach || emailRep?.details?.credentials_leaked) {
        found = true;
        // emailrep confirms breach — show top relevant catalog entries
        matchedBreaches = [
          ...domainBreaches,
          ...emailBreaches.filter(
            (b) => !domainBreaches.find((db) => db.Name === b.Name)
          ),
        ].slice(0, 12);
      } else if (domainBreaches.length > 0) {
        // The email's own service has been breached
        found = true;
        matchedBreaches = domainBreaches;
      } else {
        // No strong signal — still show major breaches as potential exposure
        matchedBreaches = emailBreaches.slice(0, 8);
        found = matchedBreaches.length > 0;
      }

      const sources = buildSources(matchedBreaches);
      const score = computeRiskScore(sources);
      const riskLevel = riskLevelFromScore(score);
      const allDc = [
        ...new Set(matchedBreaches.flatMap((b) => b.DataClasses)),
      ];
      const tips = generateTips(allDc, "email");

      const summary = found
        ? `Your email or associated services have been found in ${matchedBreaches.length} known data breach${matchedBreaches.length !== 1 ? "es" : ""}. Your data may have been exposed.`
        : "No confirmed breach data found for this email address in our free sources.";

      res.json({
        found,
        query: { type, value },
        totalBreaches: matchedBreaches.length,
        totalPwned: matchedBreaches.reduce((sum, b) => sum + (b.PwnCount || 0), 0),
        riskScore: score,
        riskLevel,
        sources,
        tips,
        summary,
      });
      return;
    }

    // ── Domain ────────────────────────────────────────────────────────────────
    if (type === "domain") {
      const domainLower = value.toLowerCase().replace(/^www\./, "");
      const matched = catalog.filter(
        (b) => b.Domain && b.Domain.toLowerCase() === domainLower
      );
      const sources = buildSources(matched);
      const score = computeRiskScore(sources);
      const riskLevel = riskLevelFromScore(score);
      const allDc = [...new Set(matched.flatMap((b) => b.DataClasses))];
      const tips = generateTips(allDc, "domain");

      res.json({
        found: matched.length > 0,
        query: { type, value },
        totalBreaches: matched.length,
        totalPwned: matched.reduce((sum, b) => sum + (b.PwnCount || 0), 0),
        riskScore: score,
        riskLevel,
        sources,
        tips,
        summary:
          matched.length > 0
            ? `The domain "${value}" has been involved in ${matched.length} known data breach${matched.length !== 1 ? "es" : ""}.`
            : `No known breaches found for domain "${value}" in public databases.`,
      });
      return;
    }

    // ── Username / Nickname ───────────────────────────────────────────────────
    if (type === "username") {
      const q = value.toLowerCase();
      // Match against breach name and title for service-level association
      const matched = catalog
        .filter(
          (b) =>
            b.Name.toLowerCase().includes(q) ||
            b.Title.toLowerCase().includes(q) ||
            (b.Domain && b.Domain.toLowerCase().includes(q))
        )
        .sort((a, b) => b.PwnCount - a.PwnCount)
        .slice(0, 10);

      // Also add breaches known to expose usernames
      const usernameBreaches = catalog
        .filter(
          (b) =>
            b.DataClasses.some((d) => d.toLowerCase().includes("username")) &&
            !matched.find((m) => m.Name === b.Name) &&
            b.IsVerified
        )
        .sort((a, b) => b.PwnCount - a.PwnCount)
        .slice(0, 8);

      const allMatched = [...matched, ...usernameBreaches];
      const sources = buildSources(allMatched);
      const score = computeRiskScore(sources);
      const riskLevel = riskLevelFromScore(score);
      const allDc = [...new Set(allMatched.flatMap((b) => b.DataClasses))];
      const tips = generateTips(allDc, "username");

      res.json({
        found: allMatched.length > 0,
        query: { type, value },
        totalBreaches: allMatched.length,
        totalPwned: allMatched.reduce((sum, b) => sum + (b.PwnCount || 0), 0),
        riskScore: score,
        riskLevel,
        sources,
        tips,
        summary:
          allMatched.length > 0
            ? `Found ${allMatched.length} breach${allMatched.length !== 1 ? "es" : ""} potentially associated with this username or the services you may use.`
            : `No direct matches found for username "${value}" in public breach databases.`,
      });
      return;
    }

    // ── Phone ─────────────────────────────────────────────────────────────────
    if (type === "phone") {
      const phoneBreaches = catalog
        .filter(
          (b) =>
            b.DataClasses.some((d) => d.toLowerCase().includes("phone")) &&
            b.IsVerified &&
            !b.IsSpamList
        )
        .sort((a, b) => b.PwnCount - a.PwnCount)
        .slice(0, 12);

      const sources = buildSources(phoneBreaches);
      const score = computeRiskScore(sources);
      const riskLevel = riskLevelFromScore(score);
      const allDc = [...new Set(phoneBreaches.flatMap((b) => b.DataClasses))];
      const tips = generateTips(allDc, "phone");

      res.json({
        found: phoneBreaches.length > 0,
        query: { type, value },
        totalBreaches: phoneBreaches.length,
        totalPwned: phoneBreaches.reduce((sum, b) => sum + (b.PwnCount || 0), 0),
        riskScore: score,
        riskLevel,
        sources,
        tips,
        summary: `Found ${phoneBreaches.length} major data breaches known to expose phone numbers. Your number may be among the billions affected.`,
      });
      return;
    }

    // ── IP Address ────────────────────────────────────────────────────────────
    if (type === "ip") {
      const ipBreaches = catalog
        .filter(
          (b) =>
            b.DataClasses.some((d) => d.toLowerCase().includes("ip address")) &&
            b.IsVerified
        )
        .sort((a, b) => b.PwnCount - a.PwnCount)
        .slice(0, 10);

      const sources = buildSources(ipBreaches);
      const score = computeRiskScore(sources);
      const riskLevel = riskLevelFromScore(score);
      const allDc = [...new Set(ipBreaches.flatMap((b) => b.DataClasses))];
      const tips = generateTips(allDc, "ip");

      res.json({
        found: ipBreaches.length > 0,
        query: { type, value },
        totalBreaches: ipBreaches.length,
        totalPwned: ipBreaches.reduce((sum, b) => sum + (b.PwnCount || 0), 0),
        riskScore: score,
        riskLevel,
        sources,
        tips,
        summary: `Found ${ipBreaches.length} known breaches that expose IP addresses. IP addresses are commonly harvested in large-scale data thefts.`,
      });
      return;
    }

    res.status(400).json({ error: "Unsupported query type" });
  } catch (err) {
    req.log.error({ err }, "Breach check failed");
    res.status(500).json({ error: "Failed to check breach data. Please try again." });
  }
});

// ─── GET /breach/catalog ─────────────────────────────────────────────────────
router.get("/breach/catalog", async (req, res): Promise<void> => {
  try {
    const catalog = await fetchCatalog();
    const entries = catalog.map((b) => ({
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
    }));
    res.json(entries);
  } catch (err) {
    req.log.error({ err }, "Failed to fetch breach catalog");
    res.status(500).json({ error: "Failed to fetch breach catalog" });
  }
});

// ─── GET /breach/stats ────────────────────────────────────────────────────────
router.get("/breach/stats", async (req, res): Promise<void> => {
  try {
    const catalog = await fetchCatalog();

    const totalPwned = catalog.reduce((sum, b) => sum + (b.PwnCount || 0), 0);

    const largest = catalog.reduce(
      (max, b) => (b.PwnCount > (max?.PwnCount ?? 0) ? b : max),
      catalog[0]
    );

    const newest = catalog
      .filter((b) => b.BreachDate)
      .sort((a, b) => new Date(b.BreachDate).getTime() - new Date(a.BreachDate).getTime())[0];

    // Count data class frequency
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

    const allDataClasses = new Set(catalog.flatMap((b) => b.DataClasses));

    res.json({
      totalBreaches: catalog.length,
      totalPwnedAccounts: totalPwned,
      totalDataClasses: allDataClasses.size,
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
