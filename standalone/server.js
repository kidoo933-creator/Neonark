const express = require("express");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.use(express.json());

// Serve index.html explicitly for the root path (Windows-safe)
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.use(express.static(path.join(__dirname)));

// SPA fallback — serve index.html for any non-API GET
app.get("*", (req, res, next) => {
  if (req.path.startsWith("/api/")) return next();
  res.sendFile(path.join(__dirname, "index.html"));
});

// ─── RockYou top-500 common passwords ─────────────────────────────────────────
const ROCKYOU_TOP = new Set([
  "123456","password","12345678","qwerty","123456789","12345","1234","111111",
  "1234567","dragon","123123","baseball","iloveyou","trustno1","1234567890",
  "superman","qazwsx","master","monkey","letmein","login","princess","solo",
  "passw0rd","starwars","whatever","shadow","michael","football","batman",
  "hello","charlie","donald","password1","password123","abc123","pass","test",
  "admin","guest","user","root","qwerty123","12341234","1qaz2wsx","1q2w3e4r",
  "zxcvbnm","sunshine","mustang","access","harley","ranger","dakota","cookie",
  "hunter","buster","soccer","george","jordan","computer","flower","cheese",
  "ginger","liverpool","chelsea","thomas","jessica","daniel","andrew","corvette",
  "scooter","pepper","hockey","snoopy","secret","sparky","1111","0000","1234qwer",
  "phoenix","qwerty12","letmein1","password2","master1","121212","696969",
  "111222","987654321","55555","888888","777777","999999","333333","444444",
  "666666","555555","123321","987654","789456","147258","258369","159753",
  "1111111","qwerty1","tigger","change","p@ssw0rd","p@ssword","pa$$word",
  "abc1234","pass123","test123","user123","admin123","hello123","iloveyou1",
  "monkey1","shadow1","dragon1","master2","passpass","1234pass","qwert","asdf",
  "zxcv","1234554321","abcdef","a1b2c3","111111a","aaa111","pass1234",
  "abc12345","password12","123456a","qweasd","q1w2e3","asdfgh","zxcvbn",
  "asdfghjkl","qwertyui","qwertyuiop","1q2w3e","1234567a","a123456b",
  "mypassword","mypass","testtest","adminadmin","rootroot","superuser",
  "toor","r00t","adm1n","p4ssword","passw0rd1","secur1ty","security",
  "12345abc","abcde12345","password!","password@","Password1","Password123",
  "Qwerty123","Welcome1","Summer2023","Winter2023","Spring2023","Fall2023",
]);

// ─── Remediation database ─────────────────────────────────────────────────────
const REMEDIATION_DB = {
  linkedin:  { url: "https://www.linkedin.com/psettings/data-privacy",
    steps: ["Go to linkedin.com → Me → Settings & Privacy → Data Privacy","Select 'Get a copy of your data' to see what's stored","Click 'Closing your LinkedIn account' to delete your account and data","Submit a data erasure request under GDPR at privacy.linkedin.com"] },
  adobe:     { url: "https://privacy.adobe.com/us/privacy-notice",
    steps: ["Go to account.adobe.com and change your password immediately","Enable two-factor authentication in account security settings","Submit a data deletion request at privacy.adobe.com","Review and revoke any connected third-party app access"] },
  dropbox:   { url: "https://www.dropbox.com/account/delete",
    steps: ["Go to dropbox.com/account → Security and change your password","Enable two-step verification in security settings","To delete your account, go to dropbox.com/account/delete","Revoke access for any connected apps you don't recognise"] },
  twitter:   { url: "https://twitter.com/settings/account/confirm_deactivation",
    steps: ["Go to twitter.com/settings/security and change your password","Enable two-factor authentication via an authenticator app","Review connected apps and revoke unknown access","Request your data archive before deleting if needed"] },
  facebook:  { url: "https://www.facebook.com/help/delete_account",
    steps: ["Go to Facebook → Settings → Your Facebook Information → Deactivation and Deletion","Change your password immediately at facebook.com/settings/security","Enable two-factor authentication","Use 'Download Your Information' before deleting your account"] },
  instagram: { url: "https://help.instagram.com/448136995230186",
    steps: ["Go to instagram.com → Settings → Security → Password and change it","Enable two-factor authentication in security settings","For account deletion: instagram.com/accounts/remove/request/permanent","Request your data download before deleting"] },
  myspace:   { url: "https://myspace.com/settings",
    steps: ["Log into Myspace and change your password","Go to Settings → Privacy to review data sharing","Contact Myspace support to request account and data deletion"] },
  canva:     { url: "https://www.canva.com/help/delete-account",
    steps: ["Go to canva.com → Account Settings → Security and change your password","Enable two-factor authentication","To delete your account: canva.com/account-delete"] },
  patreon:   { url: "https://www.patreon.com/settings",
    steps: ["Go to patreon.com/settings → Security and change your password","Enable two-factor authentication","Contact Patreon support at support.patreon.com to delete your account"] },
};

function getRemediation(serviceName, domain, breachDate) {
  const key = (serviceName + " " + (domain || "")).toLowerCase();
  for (const [dbKey, data] of Object.entries(REMEDIATION_DB)) {
    if (key.includes(dbKey)) {
      return { service: serviceName, domain, dataDeleteUrl: data.url, steps: data.steps, breachDate };
    }
  }
  const domainUrl = domain ? `https://${domain}` : null;
  return {
    service: serviceName, domain, dataDeleteUrl: domainUrl,
    steps: [
      `Go to ${domain || serviceName + "'s website"} and change your password immediately`,
      "Enable two-factor authentication if the service supports it",
      `Email ${domain || "the service"}'s privacy team citing GDPR Article 17 (Right to Erasure) to request full data deletion`,
      "If the service is EU-based, file a complaint with your national Data Protection Authority if they don't respond within 30 days",
      "Monitor your email for phishing attempts referencing this service",
    ],
    breachDate,
  };
}

// ─── Platform presence checker ────────────────────────────────────────────────
async function checkPlatforms(username) {
  const checks = [
    { name: "GitHub", reputation: "major", url: `https://github.com/${username}`,
      fetch: () => fetch(`https://api.github.com/users/${encodeURIComponent(username)}`,
        { headers: { "User-Agent": "GuardianScan/1.0" }, signal: AbortSignal.timeout(4000) }) },
    { name: "Reddit", reputation: "major", url: `https://reddit.com/u/${username}`,
      fetch: () => fetch(`https://www.reddit.com/user/${encodeURIComponent(username)}/about.json`,
        { headers: { "User-Agent": "GuardianScan/1.0" }, signal: AbortSignal.timeout(4000) }) },
  ];
  const results = await Promise.allSettled(checks.map(async (p) => {
    const r = await p.fetch();
    return { name: p.name, url: p.url, reputation: p.reputation, exists: r.status === 200 };
  }));
  return results.filter(r => r.status === "fulfilled").map(r => r.value);
}

// ─── Heuristic score when NO breach data found ────────────────────────────────
function heuristicPrivacyScore(type, value) {
  if (type === "email") {
    let s = 82;
    const [local = "", domain = ""] = value.split("@");
    const commonProviders = new Set(["gmail.com","yahoo.com","hotmail.com","outlook.com","aol.com","icloud.com","live.com","mail.com","msn.com","ymail.com"]);
    if (commonProviders.has((domain || "").toLowerCase())) s -= 8;
    if ((local || "").length <= 5) s -= 8;
    if ((local || "").length >= 16) s += 6;
    if (/\d/.test(local || "")) s -= 4;
    if (/^(info|admin|support|contact|help|no.?reply|webmaster|noreply|sales|mail|office)\d*$/i.test(local || "")) s -= 12;
    if (/^(john|jane|mike|sarah|david|chris|james|mary|robert|linda|michael|richard|thomas|daniel|mark|paul|kevin|jason|matthew|gary|stephen|andrew|peter|alex|nick|ben|sam|max|tom|emma|olivia|sophia|mia|emily|ella|lily|anna|kate|lisa|laura|amy|jessica|ashley|amanda|jennifer|melissa|rachel|karen|nancy|betty|helen)\d*$/i.test(local || "")) s -= 10;
    return Math.max(55, Math.min(90, Math.round(s)));
  }

  if (type === "username") {
    let s = 79;
    const lower = value.toLowerCase();
    if (/^(admin|administrator|user|test|guest|root|demo|default|support|service|info|webmaster|master|manager|moderator|staff|operator|superuser|sysadmin|helpdesk|anonymous|nobody|system)\d*$/.test(lower)) s = 53;
    else if (/^(john|jane|mike|sarah|david|chris|james|mary|robert|linda|michael|richard|thomas|daniel|mark|paul|kevin|jason|matthew|gary|stephen|andrew|peter|alex|nick|ben|sam|max|tom|emma|olivia|sophia|mia|emily|ella|lily|anna|kate|lisa|laura|amy|jessica|ashley|amanda|jennifer|melissa|rachel|karen|nancy|betty|helen|dorothy|ruth|sharon|carol|barbara|patricia|donna|maria|michelle|brittany|amber|heather|diana|julie|joanna)\d*$/.test(lower)) s = 58;
    if (value.length <= 4) s = Math.min(s, 60);
    if (value.length >= 14) s += 7;
    if (value.length >= 20) s += 5;
    if (/[_\-.]/.test(value) && value.length >= 8) s += 5;
    if (/[a-z]\d+[a-z]/i.test(value)) s += 3;
    return Math.max(52, Math.min(91, Math.round(s)));
  }

  if (type === "password") {
    let s = 68;
    const len = value.length;
    const hasUpper = /[A-Z]/.test(value);
    const hasLower = /[a-z]/.test(value);
    const hasDigit = /[0-9]/.test(value);
    const hasSpecial = /[^a-zA-Z0-9]/.test(value);
    const charTypes = [hasUpper, hasLower, hasDigit, hasSpecial].filter(Boolean).length;
    if (len >= 8) s += 5;
    if (len >= 12) s += 8;
    if (len >= 16) s += 9;
    if (len >= 20) s += 6;
    if (charTypes >= 3) s += 8;
    if (charTypes >= 4) s += 6;
    if (/19[5-9]\d|20[0-2]\d/.test(value)) s -= 12;
    if (/(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)/i.test(value)) s -= 5;
    if (/(123|234|345|456|567|678|789|890|abc|bcd|cde|def)/i.test(value)) s -= 10;
    if (/(.)\1{2,}/.test(value)) s -= 8;
    if (/(password|passwd|pass|secret|login|admin|welcome|access|monkey|dragon|qwerty|love|angel|shadow|master|123456|letmein|sunshine|iloveyou)/i.test(value)) s -= 15;
    if (/^[a-zA-Z]+\d{1,4}$/.test(value) && !hasSpecial && len < 12) s -= 8;
    return Math.max(50, Math.min(100, Math.round(s)));
  }

  if (type === "phone") {
    const digits = value.replace(/\D/g, "");
    if (/(.)\1{5,}/.test(digits)) return 57;
    if (/0123456789|9876543210/.test(digits)) return 54;
    return 73;
  }

  if (type === "ip") return 79;
  if (type === "domain") return 81;
  return 76;
}

// ─── HIBP catalog cache ────────────────────────────────────────────────────────
let catalogCache = null, catalogTime = 0;
async function fetchCatalog() {
  if (catalogCache && Date.now() - catalogTime < 3600000) return catalogCache;
  const r = await fetch("https://haveibeenpwned.com/api/v3/breaches",
    { headers: { "User-Agent": "GuardianScan/1.0" } });
  if (!r.ok) throw new Error("HIBP catalog failed: " + r.status);
  catalogCache = await r.json();
  catalogTime = Date.now();
  return catalogCache;
}

// ─── HIBP k-anonymity password check ─────────────────────────────────────────
async function checkPasswordHibp(password) {
  const hash = crypto.createHash("sha1").update(password).digest("hex").toUpperCase();
  const prefix = hash.slice(0, 5), suffix = hash.slice(5);
  const r = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`,
    { headers: { "User-Agent": "GuardianScan/1.0", "Add-Padding": "true" } });
  if (!r.ok) throw new Error("HIBP password failed: " + r.status);
  const text = await r.text();
  for (const line of text.split("\n")) {
    const [hs, cs] = line.split(":");
    if (hs?.trim() === suffix) return { found: true, count: parseInt(cs?.trim() || "0", 10) };
  }
  return { found: false, count: 0 };
}

// ─── LeakCheck.io free API ────────────────────────────────────────────────────
async function checkLeakCheck(query) {
  try {
    const r = await fetch(`https://leakcheck.io/api/public?check=${encodeURIComponent(query)}`,
      { headers: { "User-Agent": "GuardianScan/1.0", Accept: "application/json" },
        signal: AbortSignal.timeout(8000) });
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
const FIELD_MAP = {
  password: "Passwords", email: "Email addresses", phone: "Phone numbers",
  username: "Usernames", name: "Names", first_name: "Names", last_name: "Names",
  address: "Physical addresses", address1: "Physical addresses",
  dob: "Dates of birth", ip: "IP addresses", ip1: "IP addresses", ip2: "IP addresses",
  ssn: "Social security numbers", credit_card: "Credit card data",
  gender: "Genders", location: "Geographic locations", city: "Geographic locations",
  country: "Geographic locations", state: "Geographic locations", zip: "ZIP codes",
};

function fieldsToDataClasses(fields) {
  const s = new Set();
  for (const f of fields) {
    const m = FIELD_MAP[f.toLowerCase()];
    if (m) s.add(m); else s.add(f.charAt(0).toUpperCase() + f.slice(1).replace(/_/g, " "));
  }
  return [...s];
}

function sourceRiskLevel(b) {
  const dc = b.DataClasses.map(d => d.toLowerCase());
  if (b.IsSensitive || dc.some(d => d.includes("credit") || d.includes("ssn") || d.includes("passport"))) return "critical";
  if (dc.some(d => d.includes("password") || d.includes("pin"))) return "high";
  if (dc.some(d => d.includes("phone") || d.includes("address") || d.includes("date of birth"))) return "medium";
  return "low";
}

function matchToCatalog(sources, catalog) {
  const matched = [], unmatched = [], used = new Set();
  for (const src of sources) {
    const raw = src.name.toLowerCase();
    const stripped = raw.replace(/\.(com|net|org|io|me|fr|vn|ru|de|uk|in|co)$/i, "").replace(/[^a-z0-9]/g, "");
    let found = catalog.find(b => {
      const bn = b.Name.toLowerCase().replace(/[^a-z0-9]/g, "");
      const bt = b.Title.toLowerCase().replace(/[^a-z0-9]/g, "");
      const bd = (b.Domain || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      return bn === stripped || bt === stripped || bd === stripped || bd.startsWith(stripped) || stripped.startsWith(bn);
    });
    if (!found) found = catalog.find(b => (b.Domain || "").toLowerCase() === raw || (b.Domain || "").toLowerCase().replace("www.", "") === raw);
    if (found && !used.has(found.Name)) { matched.push(found); used.add(found.Name); }
    else if (!found) unmatched.push(src);
  }
  return { matched, unmatched };
}

function computePrivacyScore({ confirmed, leakCheckFound, fields, hibpMatches, unmatchedCount, isCommonPassword, hibpPasswordCount, platformsFound }) {
  let score = 100;
  if (!confirmed && hibpPasswordCount === 0 && !isCommonPassword) return score;
  if (confirmed) {
    score -= 20;
    if (leakCheckFound > 100000) score -= 25;
    else if (leakCheckFound > 10000) score -= 20;
    else if (leakCheckFound > 1000) score -= 15;
    else if (leakCheckFound > 100) score -= 10;
    else score -= 5;
  }
  const fl = fields.map(f => f.toLowerCase());
  if (fl.some(f => f.includes("ssn") || f.includes("social"))) score -= 20;
  if (fl.some(f => f.includes("credit") || f.includes("bank"))) score -= 18;
  if (fl.some(f => f.includes("password"))) score -= 15;
  if (fl.some(f => f.includes("dob"))) score -= 8;
  if (fl.some(f => f.includes("phone"))) score -= 5;
  let severityDeduction = 0;
  for (const b of hibpMatches) {
    if (b.IsSensitive) severityDeduction += 8;
    const rl = sourceRiskLevel(b);
    if (rl === "critical") severityDeduction += 5;
    else if (rl === "high") severityDeduction += 3;
  }
  score -= Math.min(severityDeduction, 20);
  score -= Math.min(unmatchedCount * 2, 10);
  if (isCommonPassword) score -= 35;
  if (hibpPasswordCount > 1000000) score -= 30;
  else if (hibpPasswordCount > 100000) score -= 22;
  else if (hibpPasswordCount > 1000) score -= 15;
  else if (hibpPasswordCount > 0) score -= 10;
  const activePlatforms = platformsFound.filter(p => p.exists);
  for (const p of activePlatforms) {
    if (p.reputation === "major") score -= 2;
    else if (p.reputation === "moderate") score -= 4;
    else score -= 6;
  }
  return Math.max(0, Math.min(100, Math.round(score)));
}

function privacyGrade(score) {
  if (score >= 90) return "excellent";
  if (score >= 75) return "good";
  if (score >= 50) return "fair";
  if (score >= 25) return "poor";
  return "critical";
}

function buildTips(hibpBreaches, fields, queryType, confirmed, isCommonPassword) {
  const tips = [];
  const fl = fields.map(f => f.toLowerCase());
  const allDc = [...new Set(hibpBreaches.flatMap(b => b.DataClasses.map(d => d.toLowerCase())))];
  const hasPasswords = fl.includes("password") || allDc.some(d => d.includes("password"));
  const hasPhone = fl.includes("phone") || allDc.some(d => d.includes("phone"));
  const hasSsn = fl.some(f => f.includes("ssn")) || allDc.some(d => d.includes("social security"));
  const hasFinancial = fl.some(f => f.includes("credit") || f.includes("bank")) || allDc.some(d => d.includes("credit") || d.includes("bank"));
  const sorted = [...hibpBreaches].sort((a, b) => {
    const rl = { critical: 4, high: 3, medium: 2, low: 1 };
    return (rl[sourceRiskLevel(b)] || 1) - (rl[sourceRiskLevel(a)] || 1);
  });
  for (const b of sorted.slice(0, 3)) {
    const dateStr = b.BreachDate ? new Date(b.BreachDate).toLocaleDateString("en-US", { month: "long", year: "numeric" }) : null;
    const service = b.Title || b.Name;
    const bHasPw = b.DataClasses.some(d => d.toLowerCase().includes("password"));
    const bHasFinancial = b.DataClasses.some(d => d.toLowerCase().includes("credit") || d.toLowerCase().includes("bank"));
    const bHasPhone = b.DataClasses.some(d => d.toLowerCase().includes("phone"));
    if (bHasPw && dateStr) tips.push(`Change your ${service} password immediately — breached ${dateStr}, ${(b.PwnCount || 0).toLocaleString()} accounts exposed.`);
    else if (bHasFinancial && dateStr) tips.push(`Financial data exposed in the ${service} breach (${dateStr}). Check bank statements and place a fraud alert.`);
    else if (bHasPhone && dateStr) tips.push(`Phone exposed in ${service} breach (${dateStr}). Call your carrier and add a SIM-lock PIN.`);
    else if (dateStr) tips.push(`${service} breach (${dateStr}) exposed: ${b.DataClasses.slice(0,3).join(", ")}. Change credentials and enable 2FA.`);
  }
  if (isCommonPassword) tips.push("This password is on the RockYou wordlist — change it everywhere immediately. It will be cracked in seconds.");
  if (hasPasswords && tips.length < 5) tips.push("Use a password manager (Bitwarden is free) to generate unique passwords for every account.");
  if (confirmed && tips.length < 5) tips.push("Enable two-factor authentication on email, banking, and social accounts.");
  if (hasSsn) tips.push("SSN exposed — freeze credit at Equifax, Experian, TransUnion. File an identity theft report at identitytheft.gov.");
  if (hasFinancial && !hasSsn) tips.push("Financial data exposed. Set up transaction alerts and monitor for unauthorized charges.");
  if (hasPhone && tips.length < 5) tips.push("Phone number in breach data. Add a SIM-lock PIN to prevent SIM-swap attacks.");
  if (queryType === "email" && confirmed && tips.length < 5) tips.push("Watch for targeted phishing emails from the breached services. Verify all login prompts manually.");
  if (queryType === "password") {
    tips.push("Never reuse this password. Generate a new unique password for every account.");
    tips.push("Enable two-factor authentication everywhere — a stolen password is useless with 2FA active.");
  }
  return [...new Set(tips)].slice(0, 6);
}

// ─── POST /api/breach/check ───────────────────────────────────────────────────
app.post("/api/breach/check", async (req, res) => {
  const { type, value } = req.body || {};
  if (!type || !value) return res.status(400).json({ error: "type and value are required" });
  const VALID = ["email", "phone", "username", "ip", "password", "domain"];
  if (!VALID.includes(type)) return res.status(400).json({ error: "Invalid type" });

  try {
    if (type === "password") {
      const hibp = await checkPasswordHibp(value);
      const isCommon = ROCKYOU_TOP.has(value.toLowerCase().trim());
      const score = computePrivacyScore({
        confirmed: hibp.found || isCommon, leakCheckFound: hibp.count, fields: hibp.found ? ["password"] : [],
        hibpMatches: [], unmatchedCount: 0, isCommonPassword: isCommon, hibpPasswordCount: hibp.count, platformsFound: [],
      });
      return res.json({
        found: hibp.found || isCommon, query: { type, value: "••••••••" },
        totalBreaches: hibp.found ? 1 : 0, totalPwned: hibp.count,
        privacyScore: score, privacyGrade: privacyGrade(score), isCommonPassword: isCommon,
        platformsFound: [], remediation: [],
        sources: (hibp.found || isCommon) ? [{
          name: "HibpPasswordDatabase",
          title: "HIBP Pwned Passwords — 14 Billion+ Records",
          date: null, domain: null, dataClasses: ["Passwords"], pwnCount: hibp.count,
          description: hibp.found
            ? `This exact password appeared ${hibp.count.toLocaleString()} times in breach databases.${isCommon ? " It also appears on the RockYou wordlist." : ""}`
            : "This password is on the RockYou wordlist (14 million most-common leaked passwords). Attackers use this list in every attack.",
          logoPath: null, isVerified: true, isSensitive: true, riskLevel: "critical",
        }] : [],
        tips: buildTips([], hibp.found ? ["password"] : [], "password", hibp.found || isCommon, isCommon),
        summary: hibp.found
          ? `Password found ${hibp.count.toLocaleString()} times in breach records. Never use this password.`
          : isCommon ? "Password is on the RockYou wordlist. Change it everywhere immediately."
          : "Password not found in any breach database. It currently appears safe.",
      });
    }

    const catalog = await fetchCatalog();

    async function handleQuery(queryType, queryValue) {
      const isUsername = queryType === "username";
      const emailDomain = queryType === "email" ? (queryValue.split("@")[1] || "").toLowerCase() : "";
      const [leakCheck, platforms] = await Promise.all([
        checkLeakCheck(queryValue),
        isUsername ? checkPlatforms(queryValue) : Promise.resolve([]),
      ]);
      const confirmed = !!(leakCheck?.success && (leakCheck.found || 0) > 0);
      const lcSources = confirmed ? (leakCheck.sources || []) : [];
      const lcFields = confirmed ? (leakCheck.fields || []) : [];
      const lcFound = leakCheck?.found || 0;
      const domainBreaches = queryType === "email"
        ? catalog.filter(b => b.Domain && b.Domain.toLowerCase() === emailDomain) : [];
      const { matched, unmatched } = matchToCatalog(lcSources, catalog);
      for (const db of domainBreaches) if (!matched.find(b => b.Name === db.Name)) matched.push(db);
      const isConfirmed = confirmed || domainBreaches.length > 0;
      if (!isConfirmed && platforms.every(p => !p.exists)) {
        const hScore = heuristicPrivacyScore(queryType, queryValue);
        const hGrade = privacyGrade(hScore);
        const notFoundTip = hScore < 65
          ? `No confirmed breach yet, but this ${queryType} follows common patterns heavily targeted by attackers. Use a more unique value and enable 2FA.`
          : hScore < 78
          ? `No confirmed breach found. This ${queryType} has some common characteristics — consider making it more unique and enabling 2FA.`
          : `No breach data found for this ${queryType} in any monitored database. Keep monitoring — new breaches are added daily.`;
        return {
          found: false, totalBreaches: 0, totalPwned: 0,
          privacyScore: hScore, privacyGrade: hGrade, isCommonPassword: false,
          platformsFound: platforms, remediation: [], sources: [],
          tips: [notFoundTip, "Enable two-factor authentication as a precautionary measure.", "Use a password manager to generate long, unique credentials for every account."],
          summary: `No confirmed breach found for this ${queryType}. Privacy score: ${hScore}/100 (${hGrade}) — based on credential analysis.`,
        };
      }
      const dataClasses = fieldsToDataClasses(lcFields);
      const stubs = unmatched.slice(0, 15).map(s => {
        const cleanName = s.name.replace(/\.(com|net|org|io|me|fr|vn|ru|de|uk|in)$/i, "");
        const domain = s.name.includes(".") ? s.name : null;
        const dateStr = s.date ? (s.date.length === 7 ? s.date + "-01" : s.date) : null;
        const fl = dataClasses.map(d => d.toLowerCase());
        const hasPw = fl.some(d => d.includes("password")), hasSsn = fl.some(d => d.includes("ssn") || d.includes("credit")), hasPhone = fl.some(d => d.includes("phone"));
        let riskLevel = "low";
        if (hasSsn) riskLevel = "critical"; else if (hasPw) riskLevel = "high"; else if (hasPhone) riskLevel = "medium";
        return { name: cleanName, title: cleanName, date: dateStr, addedDate: null, domain, dataClasses, pwnCount: null, description: `Identified as a breach source by LeakCheck OSINT database.`, logoPath: null, isVerified: true, isSensitive: hasSsn, riskLevel };
      });
      const allSources = [
        ...matched.map(b => ({ name: b.Name, title: b.Title || null, date: b.BreachDate || null, addedDate: b.AddedDate || null, domain: b.Domain || null, dataClasses: b.DataClasses, pwnCount: b.PwnCount || null, description: b.Description || null, logoPath: b.LogoPath || null, isVerified: b.IsVerified, isSensitive: b.IsSensitive, riskLevel: sourceRiskLevel(b) })),
        ...stubs,
      ];
      const remediation = matched.slice(0, 6).map(b => getRemediation(b.Title || b.Name, b.Domain || null, b.BreachDate || null));
      const score = computePrivacyScore({ confirmed: isConfirmed, leakCheckFound: lcFound, fields: lcFields, hibpMatches: matched, unmatchedCount: unmatched.length, isCommonPassword: false, hibpPasswordCount: 0, platformsFound: platforms });
      const tips = buildTips(matched, lcFields, queryType, isConfirmed, false);
      const totalPwned = matched.reduce((s, b) => s + (b.PwnCount || 0), 0);
      const activePlatforms = platforms.filter(p => p.exists);
      const platformNote = activePlatforms.length > 0 ? ` Active on ${activePlatforms.map(p => p.name).join(", ")}.` : "";
      return {
        found: true, totalBreaches: allSources.length, totalPwned,
        privacyScore: score, privacyGrade: privacyGrade(score), isCommonPassword: false,
        platformsFound: platforms, remediation, sources: allSources, tips,
        summary: `Confirmed in ${lcFound.toLocaleString()} records across ${lcSources.length || allSources.length} source(s).${dataClasses.length > 0 ? " Exposed: " + dataClasses.slice(0,4).join(", ") + "." : ""}${platformNote}`,
      };
    }

    if (["email","username","phone","ip"].includes(type)) {
      const qv = type === "phone" ? value.replace(/[\s\-().+]/g, "") : value;
      const result = await handleQuery(type, qv);
      return res.json({ query: { type, value }, ...result });
    }

    if (type === "domain") {
      const domainLower = value.toLowerCase().replace(/^www\./, "");
      const exactMatches = catalog.filter(b => b.Domain && b.Domain.toLowerCase() === domainLower);
      const leakCheck = await checkLeakCheck(domainLower);
      const lcSources = leakCheck?.success && (leakCheck.found || 0) > 0 ? (leakCheck.sources || []) : [];
      const { matched: lcMatched } = matchToCatalog(lcSources, catalog);
      const allMatched = [...exactMatches];
      for (const b of lcMatched) if (!allMatched.find(m => m.Name === b.Name)) allMatched.push(b);
      const confirmed = allMatched.length > 0;
      const score = computePrivacyScore({ confirmed, leakCheckFound: leakCheck?.found || 0, fields: leakCheck?.fields || [], hibpMatches: allMatched, unmatchedCount: 0, isCommonPassword: false, hibpPasswordCount: 0, platformsFound: [] });
      const remediation = allMatched.slice(0, 4).map(b => getRemediation(b.Title || b.Name, b.Domain || null, b.BreachDate || null));
      const totalPwned = allMatched.reduce((s, b) => s + (b.PwnCount || 0), 0);
      return res.json({
        found: confirmed, query: { type, value },
        totalBreaches: allMatched.length, totalPwned,
        privacyScore: confirmed ? score : heuristicPrivacyScore("domain", value),
        privacyGrade: confirmed ? privacyGrade(score) : privacyGrade(heuristicPrivacyScore("domain", value)),
        isCommonPassword: false, platformsFound: [], remediation,
        sources: allMatched.map(b => ({ name: b.Name, title: b.Title || null, date: b.BreachDate || null, addedDate: b.AddedDate || null, domain: b.Domain || null, dataClasses: b.DataClasses, pwnCount: b.PwnCount || null, description: b.Description || null, logoPath: b.LogoPath || null, isVerified: b.IsVerified, isSensitive: b.IsSensitive, riskLevel: sourceRiskLevel(b) })),
        tips: buildTips(allMatched, leakCheck?.fields || [], "domain", confirmed, false),
        summary: confirmed ? `Domain "${value}" involved in ${allMatched.length} confirmed breach(es), ~${totalPwned.toLocaleString()} records exposed.` : `No known breaches found for domain "${value}".`,
      });
    }

    res.status(400).json({ error: "Unsupported query type" });
  } catch (err) {
    console.error("Breach check error:", err.message);
    res.status(500).json({ error: "Failed to check breach data. Please try again." });
  }
});

app.get("/api/breach/catalog", async (req, res) => {
  try {
    const catalog = await fetchCatalog();
    res.json(catalog.map(b => ({ name: b.Name, title: b.Title, domain: b.Domain, breachDate: b.BreachDate, addedDate: b.AddedDate, pwnCount: b.PwnCount, description: b.Description, logoPath: b.LogoPath, dataClasses: b.DataClasses, isVerified: b.IsVerified, isFabricated: b.IsFabricated, isSensitive: b.IsSensitive, isRetired: b.IsRetired, isSpamList: b.IsSpamList })));
  } catch (err) { res.status(500).json({ error: "Failed to fetch catalog" }); }
});

app.get("/api/breach/stats", async (req, res) => {
  try {
    const catalog = await fetchCatalog();
    const totalPwned = catalog.reduce((s, b) => s + (b.PwnCount || 0), 0);
    const largest = catalog.reduce((max, b) => b.PwnCount > (max?.PwnCount || 0) ? b : max, catalog[0]);
    const newest = catalog.filter(b => b.BreachDate).sort((a, b) => new Date(b.BreachDate) - new Date(a.BreachDate))[0];
    const dcCount = {};
    for (const b of catalog) for (const dc of b.DataClasses) dcCount[dc] = (dcCount[dc] || 0) + 1;
    res.json({ totalBreaches: catalog.length, totalPwnedAccounts: totalPwned, totalDataClasses: new Set(catalog.flatMap(b => b.DataClasses)).size, largestBreach: { name: largest?.Name || "", pwnCount: largest?.PwnCount || 0 }, newestBreach: { name: newest?.Name || "", date: newest?.BreachDate || "" }, mostCommonDataTypes: Object.entries(dcCount).sort((a,b) => b[1]-a[1]).slice(0,10).map(([type,count]) => ({ type, count })) });
  } catch (err) { res.status(500).json({ error: "Failed to fetch stats" }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`GuardianScan running on http://localhost:${PORT}`));
