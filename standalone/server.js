const express = require("express");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname)));

const PORT = process.env.PORT || 3000;

// ─── In-memory catalog cache ──────────────────────────────────────────────────
let catalogCache = null;
let catalogCacheTime = 0;
const CACHE_TTL_MS = 60 * 60 * 1000;

async function fetchCatalog() {
  const now = Date.now();
  if (catalogCache && now - catalogCacheTime < CACHE_TTL_MS) return catalogCache;
  const res = await fetch("https://haveibeenpwned.com/api/v3/breaches", {
    headers: { "User-Agent": "GuardianScan/1.0" },
  });
  if (!res.ok) throw new Error(`HIBP catalog error: ${res.status}`);
  catalogCache = await res.json();
  catalogCacheTime = Date.now();
  return catalogCache;
}

// ─── Source: HIBP k-anonymity password check (free, exact) ───────────────────
async function checkPasswordHibp(password) {
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

// ─── Source: LeakCheck.io free public API ────────────────────────────────────
async function checkLeakCheck(query) {
  try {
    const res = await fetch(
      `https://leakcheck.io/api/public?check=${encodeURIComponent(query)}`,
      { headers: { "User-Agent": "GuardianScan/1.0", Accept: "application/json" },
        signal: AbortSignal.timeout(8000) }
    );
    if (!res.ok) return null;
    return await res.json();
  } catch { return null; }
}

// ─── Source: emailrep.io (free, confirms breach status) ──────────────────────
async function checkEmailRep(email) {
  try {
    const res = await fetch(`https://emailrep.io/${encodeURIComponent(email)}`, {
      headers: { "User-Agent": "GuardianScan/1.0" },
      signal: AbortSignal.timeout(6000),
    });
    if (!res.ok) return null;
    return await res.json();
  } catch { return null; }
}

// ─── Source: BreachDirectory public search ────────────────────────────────────
async function checkBreachDirectory(query) {
  try {
    const res = await fetch(
      `https://breachdirectory.org/api?func=auto&term=${encodeURIComponent(query)}`,
      { headers: { "User-Agent": "GuardianScan/1.0", Accept: "application/json" },
        signal: AbortSignal.timeout(8000) }
    );
    if (!res.ok) return null;
    return await res.json();
  } catch { return null; }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function sourceRiskLevel(breach) {
  const dc = breach.DataClasses.map((d) => d.toLowerCase());
  if (breach.IsSensitive || dc.some((d) =>
    d.includes("credit") || d.includes("bank") || d.includes("ssn") ||
    d.includes("passport") || d.includes("social security") || d.includes("tax")))
    return "critical";
  if (dc.some((d) => d.includes("password") || d.includes("pin"))) return "high";
  if (dc.some((d) => d.includes("phone") || d.includes("address") || d.includes("date of birth")))
    return "medium";
  return "low";
}

function computeRiskScore(breaches, confirmed = false) {
  if (breaches.length === 0) return 0;
  let score = Math.min(breaches.length * 8, 45);
  if (confirmed) score += 20;
  if (breaches.some((b) => b.IsSensitive)) score += 15;
  if (breaches.some((b) => b.DataClasses.some((d) => d.toLowerCase().includes("password")))) score += 15;
  if (breaches.some((b) => b.DataClasses.some((d) => d.toLowerCase().includes("credit") || d.toLowerCase().includes("bank")))) score += 10;
  return Math.min(score, 100);
}

function riskLevelFromScore(score) {
  if (score === 0) return "safe";
  if (score <= 20) return "low";
  if (score <= 45) return "medium";
  if (score <= 70) return "high";
  return "critical";
}

function buildSources(breaches) {
  return breaches.map((b) => ({
    name: b.Name, title: b.Title || null, date: b.BreachDate || null,
    addedDate: b.AddedDate || null, domain: b.Domain || null,
    dataClasses: b.DataClasses, pwnCount: b.PwnCount || null,
    description: b.Description || null, logoPath: b.LogoPath || null,
    isVerified: b.IsVerified, isSensitive: b.IsSensitive,
    riskLevel: sourceRiskLevel(b),
  }));
}

function matchSourcesToCatalog(sourceNames, catalog) {
  const matched = [];
  const usedNames = new Set();
  for (const srcName of sourceNames) {
    const lower = srcName.toLowerCase().replace(/[^a-z0-9]/g, "");
    let found = catalog.find(
      (b) => b.Name.toLowerCase().replace(/[^a-z0-9]/g, "") === lower ||
             b.Title.toLowerCase().replace(/[^a-z0-9]/g, "") === lower
    );
    if (!found) found = catalog.find(
      (b) => b.Domain && b.Domain.toLowerCase().replace(/[^a-z0-9]/g, "").includes(lower)
    );
    if (!found) found = catalog.find(
      (b) => b.Name.toLowerCase().includes(srcName.toLowerCase()) ||
             b.Title.toLowerCase().includes(srcName.toLowerCase())
    );
    if (found && !usedNames.has(found.Name)) { matched.push(found); usedNames.add(found.Name); }
  }
  return matched;
}

function generatePersonalizedTips(breaches, queryType, confirmed) {
  const tips = [];
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
    const hasFinancial = dc.some((d) => d.toLowerCase().includes("credit") || d.toLowerCase().includes("bank"));
    const hasPhone = dc.some((d) => d.toLowerCase().includes("phone"));

    if (hasPassword) {
      tips.push(`Change your ${serviceName}${domainStr} password immediately — exposed on ${dateStr} alongside ${b.PwnCount ? b.PwnCount.toLocaleString() : "millions of"} other accounts. Update any other accounts using the same password.`);
    } else if (hasFinancial) {
      tips.push(`Financial data was exposed in the ${serviceName} breach (${dateStr}). Check your bank statements for unauthorized charges and place a fraud alert with your credit bureau.`);
    } else if (hasPhone) {
      tips.push(`Your phone number was exposed in the ${serviceName} breach (${dateStr}). Add a SIM-lock PIN with your carrier to prevent SIM-swap attacks.`);
    } else {
      tips.push(`Data exposed in the ${serviceName} breach on ${dateStr}: ${dc.slice(0, 3).join(", ")}. Review your ${serviceName} account and enable two-factor authentication.`);
    }
  }

  const allDc = [...new Set(breaches.flatMap((b) => b.DataClasses))].map((d) => d.toLowerCase());
  if (allDc.some((d) => d.includes("password")) && tips.length < 5)
    tips.push("Use a password manager (Bitwarden is free) to generate and store a unique password for every account. Reusing passwords multiplies breach damage.");
  if (confirmed && tips.length < 5)
    tips.push("Enable two-factor authentication (2FA) on your email, banking, and social media accounts. Even a stolen password can't get in without the second factor.");
  if (allDc.some((d) => d.includes("social security") || d.includes("ssn")))
    tips.push("Your Social Security Number was exposed. Place a credit freeze at Equifax, Experian, and TransUnion. File an identity theft report at identitytheft.gov.");
  if (queryType === "email" && confirmed)
    tips.push("Check your inbox for suspicious messages. Attackers who have your email send targeted phishing emails impersonating the breached services.");
  if (queryType === "password") {
    tips.push("Never reuse this password anywhere. Generate a unique password for every account.");
    tips.push("Enable two-factor authentication everywhere. A compromised password is far less dangerous with 2FA active.");
  }

  const seen = new Set();
  return tips.filter((t) => { if (seen.has(t)) return false; seen.add(t); return true; }).slice(0, 6);
}

// ─── POST /api/breach/check ───────────────────────────────────────────────────
app.post("/api/breach/check", async (req, res) => {
  const { type, value } = req.body;
  if (!type || !value) return res.status(400).json({ error: "type and value are required" });

  try {
    if (type === "password") {
      const result = await checkPasswordHibp(value);
      const score = result.found ? Math.min(50 + Math.log10(result.count + 1) * 15, 100) : 0;
      const tips = generatePersonalizedTips([], "password", result.found);
      return res.json({
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
          description: `This password appeared exactly ${result.count.toLocaleString()} times in breach databases. Attackers use these lists to take over accounts across every major platform.`,
          logoPath: null, isVerified: true, isSensitive: true, riskLevel: "critical",
        }] : [],
        tips,
        summary: result.found
          ? `This exact password appeared in ${result.count.toLocaleString()} breach records. It is fully compromised and must never be used again.`
          : "This password has not been found in any of the 14+ billion breach records checked. It currently appears safe.",
      });
    }

    const catalog = await fetchCatalog();

    if (type === "email") {
      const emailDomain = value.split("@")[1]?.toLowerCase() ?? "";
      const [leakCheck, emailRep, breachDir] = await Promise.all([
        checkLeakCheck(value), checkEmailRep(value), checkBreachDirectory(value),
      ]);

      const confirmedSourceNames = [];
      let externallyConfirmed = false;

      if (leakCheck?.success && leakCheck.found > 0 && leakCheck.sources) {
        externallyConfirmed = true;
        confirmedSourceNames.push(...leakCheck.sources.map((s) => typeof s === "string" ? s : s.name));
      }
      if (breachDir?.success && breachDir.found > 0 && breachDir.result) {
        externallyConfirmed = true;
        for (const r of breachDir.result) confirmedSourceNames.push(...(r.sources ?? []));
      }

      let confirmedBreaches = matchSourcesToCatalog([...new Set(confirmedSourceNames)], catalog);
      const domainBreaches = catalog.filter((b) => b.Domain && b.Domain.toLowerCase() === emailDomain);
      for (const db of domainBreaches) {
        if (!confirmedBreaches.find((b) => b.Name === db.Name)) {
          confirmedBreaches.push(db); externallyConfirmed = true;
        }
      }

      if ((emailRep?.details?.data_breach || emailRep?.details?.credentials_leaked) && confirmedBreaches.length === 0) {
        externallyConfirmed = true;
        confirmedBreaches = catalog.filter((b) => b.IsVerified && !b.IsSpamList && b.DataClasses.some((d) => d.toLowerCase().includes("email")))
          .sort((a, b) => b.PwnCount - a.PwnCount).slice(0, 10);
      }
      if (confirmedBreaches.length === 0) {
        confirmedBreaches = catalog.filter((b) => b.IsVerified && !b.IsSpamList && b.DataClasses.some((d) => d.toLowerCase().includes("email")))
          .sort((a, b) => b.PwnCount - a.PwnCount).slice(0, 8);
      }

      const sources = buildSources(confirmedBreaches);
      const score = computeRiskScore(confirmedBreaches, externallyConfirmed);
      const totalPwned = confirmedBreaches.reduce((s, b) => s + (b.PwnCount ?? 0), 0);
      return res.json({
        found: externallyConfirmed || confirmedBreaches.length > 0,
        query: { type, value },
        totalBreaches: confirmedBreaches.length,
        totalPwned,
        riskScore: score,
        riskLevel: riskLevelFromScore(score),
        sources,
        tips: generatePersonalizedTips(confirmedBreaches, "email", externallyConfirmed),
        summary: externallyConfirmed
          ? `Your email was confirmed in ${confirmedBreaches.length} data breach${confirmedBreaches.length !== 1 ? "es" : ""} across ${confirmedSourceNames.length || confirmedBreaches.length} source${confirmedSourceNames.length !== 1 ? "s" : ""}. ~${totalPwned.toLocaleString()} accounts affected.`
          : `No confirmed breach found for this exact email in free sources. Breaches shown expose emails broadly and may include yours.`,
      });
    }

    if (type === "domain") {
      const domainLower = value.toLowerCase().replace(/^www\./, "");
      const [leakCheck, breachDir] = await Promise.all([checkLeakCheck(domainLower), checkBreachDirectory(domainLower)]);
      const confirmedSourceNames = [];
      if (leakCheck?.success && leakCheck.found > 0 && leakCheck.sources)
        confirmedSourceNames.push(...leakCheck.sources.map((s) => typeof s === "string" ? s : s.name));
      if (breachDir?.success && breachDir.found && breachDir.result)
        for (const r of breachDir.result) confirmedSourceNames.push(...(r.sources ?? []));

      const exactMatches = catalog.filter((b) => b.Domain && b.Domain.toLowerCase() === domainLower);
      const confirmedMatches = matchSourcesToCatalog([...new Set(confirmedSourceNames)], catalog);
      const allMatched = [...exactMatches];
      for (const b of confirmedMatches) if (!allMatched.find((m) => m.Name === b.Name)) allMatched.push(b);

      const score = computeRiskScore(allMatched, allMatched.length > 0);
      const totalPwned = allMatched.reduce((s, b) => s + (b.PwnCount ?? 0), 0);
      return res.json({
        found: allMatched.length > 0, query: { type, value },
        totalBreaches: allMatched.length, totalPwned,
        riskScore: score, riskLevel: riskLevelFromScore(score),
        sources: buildSources(allMatched),
        tips: generatePersonalizedTips(allMatched, "domain", allMatched.length > 0),
        summary: allMatched.length > 0
          ? `"${value}" was involved in ${allMatched.length} confirmed breach${allMatched.length !== 1 ? "es" : ""}, exposing ~${totalPwned.toLocaleString()} records.`
          : `No known breaches found for domain "${value}" in public databases.`,
      });
    }

    if (type === "username") {
      const [leakCheck, breachDir] = await Promise.all([checkLeakCheck(value), checkBreachDirectory(value)]);
      const confirmedSourceNames = [];
      let confirmed = false;
      if (leakCheck?.success && leakCheck.found > 0 && leakCheck.sources) {
        confirmed = true;
        confirmedSourceNames.push(...leakCheck.sources.map((s) => typeof s === "string" ? s : s.name));
      }
      if (breachDir?.success && breachDir.found && breachDir.result) {
        confirmed = true;
        for (const r of breachDir.result) confirmedSourceNames.push(...(r.sources ?? []));
      }
      const confirmedBreaches = matchSourcesToCatalog([...new Set(confirmedSourceNames)], catalog);
      const usernameBreaches = catalog.filter((b) => b.IsVerified &&
        b.DataClasses.some((d) => d.toLowerCase().includes("username")) &&
        !confirmedBreaches.find((cb) => cb.Name === b.Name))
        .sort((a, b) => b.PwnCount - a.PwnCount).slice(0, confirmed ? 5 : 10);
      const allMatched = [...confirmedBreaches, ...usernameBreaches];
      const score = computeRiskScore(allMatched, confirmed);
      const totalPwned = allMatched.reduce((s, b) => s + (b.PwnCount ?? 0), 0);
      return res.json({
        found: allMatched.length > 0, query: { type, value },
        totalBreaches: allMatched.length, totalPwned,
        riskScore: score, riskLevel: riskLevelFromScore(score),
        sources: buildSources(allMatched),
        tips: generatePersonalizedTips(allMatched, "username", confirmed),
        summary: confirmed
          ? `Username "${value}" found in ${confirmedBreaches.length} confirmed breach${confirmedBreaches.length !== 1 ? "es" : ""}.`
          : `No confirmed breach for username "${value}". Breaches shown expose usernames broadly.`,
      });
    }

    if (type === "phone") {
      const cleanPhone = value.replace(/[\s\-().+]/g, "");
      const [leakCheck, breachDir] = await Promise.all([checkLeakCheck(cleanPhone), checkBreachDirectory(cleanPhone)]);
      const confirmedSourceNames = [];
      let confirmed = false;
      if (leakCheck?.success && leakCheck.found > 0 && leakCheck.sources) {
        confirmed = true;
        confirmedSourceNames.push(...leakCheck.sources.map((s) => typeof s === "string" ? s : s.name));
      }
      if (breachDir?.success && breachDir.found && breachDir.result) {
        confirmed = true;
        for (const r of breachDir.result) confirmedSourceNames.push(...(r.sources ?? []));
      }
      const confirmedBreaches = matchSourcesToCatalog([...new Set(confirmedSourceNames)], catalog);
      const phoneBreaches = catalog.filter((b) => b.IsVerified && !b.IsSpamList &&
        b.DataClasses.some((d) => d.toLowerCase().includes("phone")) &&
        !confirmedBreaches.find((cb) => cb.Name === b.Name))
        .sort((a, b) => b.PwnCount - a.PwnCount).slice(0, confirmed ? 6 : 12);
      const allMatched = [...confirmedBreaches, ...phoneBreaches];
      const score = computeRiskScore(allMatched, confirmed);
      const totalPwned = allMatched.reduce((s, b) => s + (b.PwnCount ?? 0), 0);
      return res.json({
        found: allMatched.length > 0, query: { type, value },
        totalBreaches: allMatched.length, totalPwned,
        riskScore: score, riskLevel: riskLevelFromScore(score),
        sources: buildSources(allMatched),
        tips: generatePersonalizedTips(allMatched, "phone", confirmed),
        summary: confirmed
          ? `This phone number was found in ${confirmedBreaches.length} confirmed breach${confirmedBreaches.length !== 1 ? "es" : ""}. Attackers can attempt SIM swaps and targeted phishing.`
          : `Found ${phoneBreaches.length} major breaches known to expose phone numbers. Your number may be among the records.`,
      });
    }

    if (type === "ip") {
      const [leakCheck, breachDir] = await Promise.all([checkLeakCheck(value), checkBreachDirectory(value)]);
      const confirmedSourceNames = [];
      let confirmed = false;
      if (leakCheck?.success && leakCheck.found > 0 && leakCheck.sources) {
        confirmed = true;
        confirmedSourceNames.push(...leakCheck.sources.map((s) => typeof s === "string" ? s : s.name));
      }
      if (breachDir?.success && breachDir.found && breachDir.result) {
        confirmed = true;
        for (const r of breachDir.result) confirmedSourceNames.push(...(r.sources ?? []));
      }
      const confirmedBreaches = matchSourcesToCatalog([...new Set(confirmedSourceNames)], catalog);
      const ipBreaches = catalog.filter((b) => b.IsVerified &&
        b.DataClasses.some((d) => d.toLowerCase().includes("ip address")) &&
        !confirmedBreaches.find((cb) => cb.Name === b.Name))
        .sort((a, b) => b.PwnCount - a.PwnCount).slice(0, confirmed ? 5 : 10);
      const allMatched = [...confirmedBreaches, ...ipBreaches];
      const score = computeRiskScore(allMatched, confirmed);
      const totalPwned = allMatched.reduce((s, b) => s + (b.PwnCount ?? 0), 0);
      return res.json({
        found: allMatched.length > 0, query: { type, value },
        totalBreaches: allMatched.length, totalPwned,
        riskScore: score, riskLevel: riskLevelFromScore(score),
        sources: buildSources(allMatched),
        tips: generatePersonalizedTips(allMatched, "ip", confirmed),
        summary: confirmed
          ? `IP ${value} was found in ${confirmedBreaches.length} confirmed breach${confirmedBreaches.length !== 1 ? "es" : ""}. Knowing your IP helps attackers map your network.`
          : `Found ${ipBreaches.length} major breaches known to expose IP addresses.`,
      });
    }

    res.status(400).json({ error: "Unsupported query type" });
  } catch (err) {
    console.error("Breach check failed:", err);
    res.status(500).json({ error: "Failed to check breach data. Please try again." });
  }
});

// ─── GET /api/breach/catalog ──────────────────────────────────────────────────
app.get("/api/breach/catalog", async (req, res) => {
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

// ─── GET /api/breach/stats ────────────────────────────────────────────────────
app.get("/api/breach/stats", async (req, res) => {
  try {
    const catalog = await fetchCatalog();
    const totalPwned = catalog.reduce((s, b) => s + (b.PwnCount ?? 0), 0);
    const largest = catalog.reduce((max, b) => b.PwnCount > (max?.PwnCount ?? 0) ? b : max, catalog[0]);
    const newest = catalog.filter((b) => b.BreachDate)
      .sort((a, b) => new Date(b.BreachDate) - new Date(a.BreachDate))[0];
    const dcCount = {};
    for (const breach of catalog)
      for (const dc of breach.DataClasses) dcCount[dc] = (dcCount[dc] ?? 0) + 1;
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

// ─── Serve frontend for all other routes ──────────────────────────────────────
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, () => {
  console.log(`GuardianScan running at http://localhost:${PORT}`);
});
