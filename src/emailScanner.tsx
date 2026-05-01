import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  KeyRound,
  Loader2,
  LockKeyhole,
  MailSearch,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { motion } from "framer-motion";
import { FormEvent, useEffect, useState } from "react";

type RiskLevel = "Low" | "Medium" | "High";

type EmailCheckResult = {
  compromised: boolean;
  breach_count: number;
  risk_level: RiskLevel;
  recommendations: string[];
  message: string;
  provider?: string;
  sources?: Array<{
    name: string;
    date?: string;
  }>;
  fields?: string[];
  cached?: boolean;
  provider_limited?: boolean;
};

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

const fadeUp = {
  hidden: { opacity: 0, y: 24 },
  visible: { opacity: 1, y: 0 },
};

function riskClasses(risk: RiskLevel) {
  if (risk === "High") return "border-trace/40 bg-trace/10 text-trace";
  if (risk === "Medium") return "border-volt/40 bg-volt/10 text-volt";
  return "border-signal/40 bg-signal/10 text-signal";
}

async function readJson<T>(response: Response): Promise<T> {
  const body = await response.json().catch(() => null);

  if (!response.ok) {
    throw new Error(body?.message || "Scanner service returned an unexpected response. Please try again shortly.");
  }

  return body as T;
}

export function EmailScannerPage() {
  const [email, setEmail] = useState("");
  const [result, setResult] = useState<EmailCheckResult | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [cooldown, setCooldown] = useState(0);

  useEffect(() => {
    if (cooldown <= 0) return;

    const timer = window.setInterval(() => {
      setCooldown((remaining) => Math.max(remaining - 1, 0));
    }, 1000);

    return () => window.clearInterval(timer);
  }, [cooldown]);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (cooldown > 0) {
      setError(`Please wait ${cooldown} seconds before running another scan.`);
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();
    setError("");
    setResult(null);

    if (!emailPattern.test(normalizedEmail)) {
      setError("Enter a valid email address to scan.");
      return;
    }

    setLoading(true);
    setCooldown(60);

    try {
      const data = await fetch("/api/email-check", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({ email: normalizedEmail }),
      }).then((response) => readJson<EmailCheckResult>(response));

      setResult(data);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to check this email right now.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="relative min-h-screen px-5 py-6">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_18%_12%,rgba(252,238,10,0.14),transparent_28%),radial-gradient(circle_at_82%_8%,rgba(255,42,61,0.1),transparent_22%)]" aria-hidden="true" />
      <nav className="relative z-10 mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 rounded-lg border border-white/10 bg-obsidian/70 px-4 py-3 backdrop-blur-xl">
        <a href="/" className="glitch-control inline-flex items-center gap-2 text-sm font-semibold uppercase text-white">
          <ArrowLeft size={16} />
          Home
        </a>
        <span className="font-mono text-xs uppercase text-signal">Email exposure scanner</span>
        <span className="hidden font-mono text-xs uppercase text-white/35 sm:inline">/ LeakCheck pass-through</span>
      </nav>

      <div className="relative z-10 mx-auto grid max-w-7xl gap-8 py-14 md:py-20 lg:grid-cols-[0.9fr_1.1fr] lg:items-start">
        <motion.header initial="hidden" animate="visible" variants={fadeUp}>
          <p className="font-mono text-xs uppercase text-signal">Exposure intelligence / privacy-first lookup</p>
          <h1 className="micro-glitch-heading mt-4 max-w-4xl text-5xl font-semibold leading-tight text-white md:text-7xl" data-text="Email exposure scanner.">
            Email exposure scanner.
          </h1>
          <p className="mt-6 max-w-2xl text-lg leading-8 text-haze">
            Check whether your email has appeared in known breach or dark-web data.
          </p>
          <div className="mt-8 grid gap-3 text-sm text-haze sm:grid-cols-3">
            {[
              ["No storage", "Submitted emails are not saved."],
              ["Server-side check", "The browser only talks to this site."],
              ["Actionable result", "Risk level and guidance included."],
            ].map(([title, body]) => (
              <div key={title} className="rounded-lg border border-white/10 bg-white/[0.04] p-4 backdrop-blur-xl">
                <p className="font-mono text-xs uppercase text-signal">{title}</p>
                <p className="mt-2 leading-6">{body}</p>
              </div>
            ))}
          </div>
        </motion.header>

        <motion.section
          initial={{ opacity: 0, y: 26 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.55, delay: 0.08 }}
          className="overflow-hidden rounded-lg border border-white/10 bg-obsidian/70 shadow-glow backdrop-blur-xl"
        >
          <div className="flex items-center gap-2 border-b border-white/10 px-4 py-3">
            <span className="h-3 w-3 rounded-full bg-trace" />
            <span className="h-3 w-3 rounded-full bg-volt" />
            <span className="h-3 w-3 rounded-full bg-signal" />
            <span className="ml-2 font-mono text-xs text-haze">exposure-check.sh</span>
          </div>

          <form onSubmit={submit} className="grid gap-5 p-5 md:p-6">
            <label className="grid gap-2">
              <span className="micro-glitch-text font-mono text-xs uppercase text-signal" data-text="$ email --check">
                $ email --check
              </span>
              <div className="relative">
                <MailSearch className="pointer-events-none absolute left-5 top-1/2 -translate-y-1/2 text-haze" size={18} />
                <input
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  className="terminal-input !pl-14"
                  type="email"
                  inputMode="email"
                  autoComplete="email"
                  placeholder="you@example.com"
                  required
                />
              </div>
            </label>

            <button
              type="submit"
              disabled={loading || cooldown > 0}
              className="glitch-control inline-flex h-12 items-center justify-center gap-2 rounded-lg bg-signal px-5 text-sm font-semibold text-obsidian transition hover:bg-white disabled:cursor-not-allowed disabled:opacity-70"
            >
              {loading ? <Loader2 className="animate-spin" size={17} /> : <ShieldCheck size={17} />}
              {loading ? "Checking exposure..." : cooldown > 0 ? `Cooldown ${cooldown}s` : "Check Exposure"}
            </button>

            <p className="rounded-md border border-white/10 bg-white/[0.035] px-4 py-3 text-sm leading-6 text-haze">
              We do not store submitted emails.{" "}
              <a href="https://wiki.leakcheck.io/en/api/public" target="_blank" rel="noreferrer" className="text-signal underline decoration-signal/40 underline-offset-4 hover:text-white">
                Powered by LeakCheck.
              </a>
            </p>

            {error && (
              <div className="rounded-lg border border-trace/40 bg-trace/10 p-4 text-trace">
                <div className="flex items-center gap-2 font-mono text-xs uppercase">
                  <AlertTriangle size={16} />
                  Check failed
                </div>
                <p className="mt-2 leading-7 text-haze">{error}</p>
              </div>
            )}

            {result && (
              <div className="grid gap-4">
                <div className={["rounded-lg border p-5", result.provider_limited ? "border-volt/40 bg-volt/10 text-volt" : riskClasses(result.risk_level)].join(" ")}>
                  <div className="flex items-center gap-3">
                    {result.provider_limited ? <AlertTriangle size={24} /> : result.compromised ? <ShieldAlert size={24} /> : <CheckCircle2 size={24} />}
                    <div>
                      <p className="font-mono text-xs uppercase">{result.cached ? "Cached scan result" : "Scan result"}</p>
                      <h2 className="mt-1 text-2xl font-semibold text-white">{result.message}</h2>
                    </div>
                  </div>
                  <div className="mt-5 grid gap-3 sm:grid-cols-3">
                    <div className="rounded-md border border-white/10 bg-black/20 p-3">
                      <p className="font-mono text-xs uppercase text-haze">Compromised</p>
                      <p className="mt-1 text-xl font-semibold text-white">{result.compromised ? "Yes" : "No"}</p>
                    </div>
                    <div className="rounded-md border border-white/10 bg-black/20 p-3">
                      <p className="font-mono text-xs uppercase text-haze">Breach count</p>
                      <p className="mt-1 text-xl font-semibold text-white">{result.breach_count}</p>
                    </div>
                    <div className="rounded-md border border-white/10 bg-black/20 p-3">
                      <p className="font-mono text-xs uppercase text-haze">Risk level</p>
                      <p className="mt-1 text-xl font-semibold text-white">{result.risk_level}</p>
                    </div>
                  </div>
                </div>

                {result.compromised && ((result.sources?.length || 0) > 0 || (result.fields?.length || 0) > 0) && (
                  <div className="rounded-lg border border-white/10 bg-white/[0.04] p-5">
                    <div className="mb-4 flex items-center gap-2 font-mono text-xs uppercase text-signal">
                      <MailSearch size={16} />
                      Exposure details
                    </div>

                    {(result.fields?.length || 0) > 0 && (
                      <div>
                        <p className="font-mono text-xs uppercase text-haze">What data types appeared</p>
                        <div className="mt-3 flex flex-wrap gap-2">
                          {result.fields?.map((field) => (
                            <span key={field} className="rounded-md border border-white/10 bg-black/20 px-3 py-2 text-sm text-white">
                              {field}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {(result.sources?.length || 0) > 0 && (
                      <div className={(result.fields?.length || 0) > 0 ? "mt-6" : ""}>
                        <p className="font-mono text-xs uppercase text-haze">Where and when it appeared</p>
                        <div className="mt-3 grid gap-2 sm:grid-cols-2">
                          {result.sources?.map((source) => (
                            <div key={`${source.name}-${source.date || "unknown"}`} className="flex items-center justify-between gap-3 rounded-md border border-white/10 bg-black/20 px-3 py-2">
                              <span className="text-sm font-medium text-white">{source.name}</span>
                              <span className="shrink-0 font-mono text-xs uppercase text-haze">{source.date || "Date unknown"}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                <div className="rounded-lg border border-white/10 bg-white/[0.04] p-5">
                  <div className="mb-4 flex items-center gap-2 font-mono text-xs uppercase text-signal">
                    <LockKeyhole size={16} />
                    Recommendations
                  </div>
                  <ul className="grid gap-3">
                    {result.recommendations.map((recommendation) => (
                      <li key={recommendation} className="flex gap-3 leading-7 text-haze">
                        <KeyRound className="mt-1 shrink-0 text-signal" size={16} />
                        <span>{recommendation}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )}
          </form>
        </motion.section>
      </div>
    </div>
  );
}
