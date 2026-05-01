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
type ProviderStatus = "matched" | "clean" | "rate_limited" | "unavailable" | "not_configured" | "error" | string;

type ExposureRecord = {
  title: string;
  name?: string;
  domain?: string;
  breach_date?: string;
  added_date?: string;
  modified_date?: string;
  pwn_count?: number;
  data_classes?: string[];
  fields?: string[];
  providers?: string[];
  flags?: Record<string, boolean>;
};

type EmailCheckResult = {
  compromised: boolean;
  breach_count: number;
  risk_level: RiskLevel;
  recommendations: string[];
  message: string;
  provider?: string;
  exposures?: ExposureRecord[];
  data_classes?: string[];
  risk_reasons?: string[];
  providers_checked?: string[];
  provider_status?: Record<string, ProviderStatus>;
  provider_errors?: Record<string, string>;
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
  return "border-cyan-300/40 bg-cyan-400/10 text-cyan-100 shadow-[0_0_34px_rgba(103,232,249,0.12)]";
}

function statusClasses(status: ProviderStatus) {
  if (status === "matched") return "border-signal/35 bg-signal/10 text-signal";
  if (status === "clean") return "border-cyan-300/35 bg-cyan-400/10 text-cyan-100";
  if (status === "rate_limited") return "border-volt/40 bg-volt/10 text-volt";
  return "border-trace/35 bg-trace/10 text-trace";
}

function prettyStatus(status: ProviderStatus) {
  return status.replace(/_/g, " ");
}

function prettyFlag(flag: string) {
  return flag.replace(/_/g, " ");
}

function activeFlags(flags?: Record<string, boolean>) {
  return Object.entries(flags || {}).filter(([, enabled]) => enabled);
}

function exposureData(exposure: ExposureRecord) {
  return [...new Set([...(exposure.data_classes || []), ...(exposure.fields || [])].filter(Boolean))];
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
        <span className="font-mono text-xs uppercase text-signal">Identity exposure scanner</span>
      </nav>

      <div className="relative z-10 mx-auto grid max-w-7xl gap-8 py-14 md:py-20 lg:grid-cols-[0.9fr_1.1fr] lg:items-start">
        <motion.header initial="hidden" animate="visible" variants={fadeUp}>
          <p className="font-mono text-xs uppercase text-signal">Exposure intelligence / privacy-first lookup</p>
          <h1 className="micro-glitch-heading mt-4 max-w-4xl text-5xl font-semibold leading-tight text-white md:text-7xl" data-text="Identity exposure scanner.">
            Identity exposure scanner.
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
              Submitted emails are checked server-side and not stored by this site. Powered by{" "}
              <a href="https://haveibeenpwned.com/API/v3" target="_blank" rel="noreferrer" className="text-signal underline decoration-signal/40 underline-offset-4 hover:text-white">
                Have I Been Pwned
              </a>{" "}
              and{" "}
              <a href="https://wiki.leakcheck.io/en/api/public" target="_blank" rel="noreferrer" className="text-signal underline decoration-signal/40 underline-offset-4 hover:text-white">
                LeakCheck
              </a>
              .
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

                {Object.keys(result.provider_status || {}).length > 0 && (
                  <div className="rounded-lg border border-white/10 bg-white/[0.04] p-5">
                    <div className="mb-4 flex items-center gap-2 font-mono text-xs uppercase text-signal">
                      <ShieldCheck size={16} />
                      Provider status
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {Object.entries(result.provider_status || {}).map(([provider, status]) => (
                        <span key={provider} className={["rounded-md border px-3 py-2 font-mono text-xs uppercase", statusClasses(status)].join(" ")}>
                          {provider}: {prettyStatus(status)}
                        </span>
                      ))}
                    </div>
                    {Object.keys(result.provider_errors || {}).length > 0 && (
                      <div className="mt-4 grid gap-2">
                        {Object.entries(result.provider_errors || {}).map(([provider, note]) => (
                          <p key={provider} className="text-sm leading-6 text-haze">
                            <span className="font-semibold text-white">{provider}:</span> {note}
                          </p>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {(result.risk_reasons?.length || 0) > 0 && (
                  <div className="rounded-lg border border-white/10 bg-white/[0.04] p-5">
                    <div className="mb-4 flex items-center gap-2 font-mono text-xs uppercase text-signal">
                      <AlertTriangle size={16} />
                      Risk intelligence
                    </div>
                    <ul className="grid gap-2">
                      {result.risk_reasons?.map((reason) => (
                        <li key={reason} className="leading-7 text-haze">
                          {reason}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {result.compromised && (result.exposures?.length || 0) > 0 && (
                  <div className="rounded-lg border border-white/10 bg-white/[0.04] p-5">
                    <div className="mb-4 flex items-center gap-2 font-mono text-xs uppercase text-signal">
                      <MailSearch size={16} />
                      Exposure intelligence
                    </div>
                    <div className="grid gap-3">
                      {result.exposures?.map((exposure, index) => {
                        const data = exposureData(exposure);
                        const flags = activeFlags(exposure.flags);

                        return (
                          <article key={`${exposure.title}-${exposure.breach_date || exposure.added_date || index}`} className="rounded-lg border border-white/10 bg-black/20 p-4">
                            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                              <div>
                                <h3 className="text-lg font-semibold text-white">{exposure.title}</h3>
                                <div className="mt-2 flex flex-wrap gap-2 text-xs text-haze">
                                  {exposure.domain && <span className="rounded border border-white/10 bg-white/[0.04] px-2 py-1">{exposure.domain}</span>}
                                  {exposure.breach_date && <span className="rounded border border-white/10 bg-white/[0.04] px-2 py-1">Breach: {exposure.breach_date}</span>}
                                  {exposure.added_date && <span className="rounded border border-white/10 bg-white/[0.04] px-2 py-1">Added: {exposure.added_date.slice(0, 10)}</span>}
                                  {typeof exposure.pwn_count === "number" && <span className="rounded border border-white/10 bg-white/[0.04] px-2 py-1">{exposure.pwn_count.toLocaleString()} accounts</span>}
                                </div>
                              </div>
                              <div className="flex shrink-0 flex-wrap gap-2">
                                {(exposure.providers || []).map((provider) => (
                                  <span key={provider} className="rounded-md border border-signal/30 bg-signal/10 px-2.5 py-1 font-mono text-[11px] uppercase text-signal">
                                    {provider}
                                  </span>
                                ))}
                              </div>
                            </div>

                            {data.length > 0 && (
                              <div className="mt-4">
                                <p className="font-mono text-xs uppercase text-haze">Data exposed</p>
                                <div className="mt-2 flex flex-wrap gap-2">
                                  {data.map((field) => (
                                    <span key={field} className="rounded-md border border-white/10 bg-white/[0.04] px-3 py-2 text-sm text-white">
                                      {field}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )}

                            {flags.length > 0 && (
                              <div className="mt-4 flex flex-wrap gap-2">
                                {flags.map(([flag]) => (
                                  <span key={flag} className="rounded-md border border-volt/30 bg-volt/10 px-2.5 py-1 font-mono text-[11px] uppercase text-volt">
                                    {prettyFlag(flag)}
                                  </span>
                                ))}
                              </div>
                            )}
                          </article>
                        );
                      })}
                    </div>
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
