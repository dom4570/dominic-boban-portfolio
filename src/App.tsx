import {
  Activity,
  ArrowDown,
  BadgeCheck,
  BriefcaseBusiness,
  Bug,
  ChevronRight,
  Code2,
  DatabaseZap,
  Download,
  ExternalLink,
  FileSearch,
  Github,
  GraduationCap,
  Linkedin,
  Mail,
  MapPin,
  Medal,
  Network,
  Radar,
  ScanSearch,
  ServerCog,
  Shield,
  ShieldCheck,
  Sparkles,
  Terminal,
  Trophy,
} from "lucide-react";
import { motion, useReducedMotion } from "framer-motion";
import { FormEvent, ReactNode, useEffect, useRef, useState } from "react";

type IconType = typeof Shield;

const navItems = [
  { label: "About", href: "#about" },
  { label: "Skills", href: "#skills" },
  { label: "Experience", href: "#experience" },
  { label: "Projects", href: "#projects" },
  { label: "Achievements", href: "#achievements" },
  { label: "Contact", href: "#contact" },
];

const securityTools = [
  "Splunk",
  "ELK",
  "Wazuh",
  "Burp Suite",
  "Metasploit",
  "Nmap",
  "Wireshark",
  "OpenVAS",
  "Nikto",
  "sqlmap",
  "BloodHound",
];

const skillGroups = [
  {
    title: "Security Tools",
    icon: Radar,
    accent: "signal",
    items: securityTools,
  },
  {
    title: "Cloud & DevSecOps",
    icon: ServerCog,
    accent: "volt",
    items: ["AWS EC2", "AWS S3", "Azure AD", "Docker", "Terraform reviews"],
  },
  {
    title: "Scripting",
    icon: Code2,
    accent: "trace",
    items: ["Python", "Bash", "PowerShell", "SQL"],
  },
  {
    title: "Frameworks",
    icon: FileSearch,
    accent: "signal",
    items: ["OWASP Top 10", "PTES", "NIST SP 800-115", "MITRE ATT&CK"],
  },
  {
    title: "Testing Areas",
    icon: ScanSearch,
    accent: "volt",
    items: [
      "Web App Security",
      "API Security",
      "Active Directory",
      "Network Security",
      "Container Security",
      "Vulnerability Management",
      "Dark Web Monitoring",
    ],
  },
];

const experience = [
  {
    company: "Baseel Partners",
    role: "Cyber Security Penetration Tester",
    period: "Jul 2025 - Present",
    location: "London",
    icon: ShieldCheck,
    points: [
      "Perform penetration tests and vulnerability assessments across web applications, networks, and infrastructure.",
      "Develop automated SOC monitoring, CVE scraping, and vulnerability detection pipelines for faster threat discovery.",
      "Integrate results with SIEM platforms including Splunk, ELK, and Wazuh to strengthen detection engineering.",
      "Build Python and Bash tooling for reconnaissance, vulnerability tracking, and remediation validation.",
      "Monitor dark web exposure, conduct OSINT investigations, and translate findings into executive-ready reporting.",
    ],
  },
  {
    company: "Amorino",
    role: "Retail Supervisor",
    period: "Jun 2022 - Jul 2025",
    location: "Knightsbridge",
    icon: BriefcaseBusiness,
    points: [
      "Progressed from Sales Assistant to Supervisor while studying, leading staff training, shift operations, and service quality.",
      "Managed a multicultural team with a focus on performance, policy adherence, reporting, scheduling, and inventory discipline.",
      "Built calm operational leadership habits that now support stakeholder communication and high-pressure security work.",
    ],
  },
  {
    company: "Sycuris Labs",
    role: "SOC Level 1 Intern",
    period: "Oct 2021 - Jan 2022",
    location: "Bengaluru",
    icon: Activity,
    points: [
      "Monitored SIEM dashboards for suspicious logins, malware indicators, and anomalous network traffic.",
      "Performed L1 triage, IOC enrichment, log analysis, and escalation notes for L2 and incident response teams.",
      "Automated recurring log parsing and IOC lookups with Python and Bash to accelerate investigations.",
      "Supported basic cloud security reviews and policy enforcement activities.",
    ],
  },
];

const projects = [
  {
    title: "CVE Scraping Automation",
    kicker: "Threat intelligence pipeline",
    icon: Bug,
    metric: "Faster vulnerability discovery",
    body: "Automated collection and enrichment workflows that surface relevant CVEs, reduce manual triage, and support proactive remediation.",
  },
  {
    title: "Dark Web Exposure Monitor",
    kicker: "Credential intelligence",
    icon: DatabaseZap,
    metric: "Earlier breach indicators",
    body: "Portfolio-safe monitoring concept based on Dominic's work identifying leaked credentials and sensitive exposure signals before they become incidents.",
  },
  {
    title: "SIEM Detection Pipeline",
    kicker: "SOC automation",
    icon: Network,
    metric: "Improved detection coverage",
    body: "Splunk, ELK, and Wazuh-aligned workflows that turn assessment findings into monitored signals and practical response visibility.",
  },
  {
    title: "Assessment Reporting System",
    kicker: "Technical to executive clarity",
    icon: FileSearch,
    metric: "Actionable remediation",
    body: "Risk-based reporting structure for vulnerability validation, developer guidance, and concise executive summaries.",
  },
];

const achievements = [
  {
    title: "Top 800 Hack The Box",
    icon: Trophy,
    detail: "Ranked among the top 800 hackers globally through hands-on penetration testing and cybersecurity challenges.",
  },
  {
    title: "Microsoft Hall of Fame",
    icon: Medal,
    detail: "Recognised for security-focused cloud framework contributions and responsible security research.",
  },
  {
    title: "Automated CVE Scraping",
    icon: Bug,
    detail: "Built systems that shorten the time between new vulnerability disclosure and internal detection awareness.",
  },
  {
    title: "Dark Web Monitoring",
    icon: Radar,
    detail: "Designed tools for identifying leaked credentials and sensitive data exposure across external threat sources.",
  },
  {
    title: "Enhanced Detection Pipelines",
    icon: Activity,
    detail: "Connected offensive findings with SOC workflows to improve alert quality, enrichment, and threat visibility.",
  },
];

const certifications = [
  {
    name: "CCPENT",
    issuer: "EC-Council",
    status: "In Progress",
    date: "Jan 2026",
  },
  {
    name: "Certified Cyber Security Technician",
    issuer: "EC-Council",
    status: "Certified",
    date: "Dec 2024",
  },
  {
    name: "SOC Level 1",
    issuer: "Personal Tutor",
    status: "Certified",
    date: "Dec 2024",
  },
  {
    name: "CRTA",
    issuer: "Red Team Hacker Academy",
    status: "Certified",
    date: "Aug 2023",
  },
  {
    name: "CPT",
    issuer: "Red Team Hacker Academy",
    status: "Certified",
    date: "Oct 2023",
  },
];

const profileStats = [
  { value: "2+", label: "Years security experience" },
  { value: "800", label: "Global HTB ranking" },
  { value: "5", label: "Security certifications" },
  { value: "24/7", label: "Adversarial mindset" },
];

const terminalLines = [
  "$ nmap --top-ports 1000 dominic-boban.security",
  "22/tcp open ssh  | hardened",
  "443/tcp open https | portfolio live",
  "$ python detect_exposure.py --sources darkweb --mode passive",
  "status: monitoring exposure, CVEs, and anomalous signals",
];

const containerVariants = {
  hidden: {},
  visible: {
    transition: {
      staggerChildren: 0.08,
    },
  },
};

const itemVariants = {
  hidden: { opacity: 0, y: 22 },
  visible: { opacity: 1, y: 0 },
};

function cn(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(" ");
}

function CyberCanvas() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const reduceMotion = useReducedMotion();

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const context = canvas.getContext("2d");
    if (!context) return;

    let animationFrame = 0;
    let width = 0;
    let height = 0;
    const particles = Array.from({ length: 76 }, (_, index) => ({
      x: (index * 97) % 1200,
      y: (index * 193) % 800,
      vx: ((index % 7) - 3) * 0.09,
      vy: ((index % 5) - 2) * 0.08,
      r: 1 + (index % 3) * 0.45,
    }));

    const resize = () => {
      const ratio = window.devicePixelRatio || 1;
      width = canvas.offsetWidth;
      height = canvas.offsetHeight;
      canvas.width = Math.max(1, Math.floor(width * ratio));
      canvas.height = Math.max(1, Math.floor(height * ratio));
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
    };

    const draw = () => {
      context.clearRect(0, 0, width, height);

      const gradient = context.createRadialGradient(width * 0.55, height * 0.35, 20, width * 0.55, height * 0.35, width * 0.8);
      gradient.addColorStop(0, "rgba(252, 238, 10, 0.13)");
      gradient.addColorStop(0.45, "rgba(255, 42, 61, 0.08)");
      gradient.addColorStop(1, "rgba(5, 7, 13, 0)");
      context.fillStyle = gradient;
      context.fillRect(0, 0, width, height);

      context.strokeStyle = "rgba(252, 238, 10, 0.09)";
      context.lineWidth = 1;
      const grid = 54;
      for (let x = (performance.now() * 0.006) % grid; x < width; x += grid) {
        context.beginPath();
        context.moveTo(x, 0);
        context.lineTo(x - width * 0.18, height);
        context.stroke();
      }
      for (let y = 0; y < height; y += grid) {
        context.beginPath();
        context.moveTo(0, y);
        context.lineTo(width, y + height * 0.12);
        context.stroke();
      }

      particles.forEach((particle, index) => {
        if (!reduceMotion) {
          particle.x += particle.vx;
          particle.y += particle.vy;
        }
        if (particle.x < -20) particle.x = width + 20;
        if (particle.x > width + 20) particle.x = -20;
        if (particle.y < -20) particle.y = height + 20;
        if (particle.y > height + 20) particle.y = -20;

        context.fillStyle = index % 6 === 0 ? "rgba(255, 42, 61, 0.6)" : "rgba(252, 238, 10, 0.52)";
        context.beginPath();
        context.arc(particle.x % width, particle.y % height, particle.r, 0, Math.PI * 2);
        context.fill();

        particles.slice(index + 1).forEach((other) => {
          const dx = particle.x - other.x;
          const dy = particle.y - other.y;
          const distance = Math.sqrt(dx * dx + dy * dy);
          if (distance < 124) {
            context.strokeStyle = `rgba(252, 238, 10, ${0.12 - distance / 1400})`;
            context.beginPath();
            context.moveTo(particle.x, particle.y);
            context.lineTo(other.x, other.y);
            context.stroke();
          }
        });
      });

      if (!reduceMotion) {
        animationFrame = requestAnimationFrame(draw);
      }
    };

    resize();
    draw();
    window.addEventListener("resize", resize);

    return () => {
      window.removeEventListener("resize", resize);
      cancelAnimationFrame(animationFrame);
    };
  }, [reduceMotion]);

  return <canvas ref={canvasRef} className="pointer-events-none absolute inset-0 h-full w-full opacity-90" aria-hidden="true" />;
}

function SectionHeader({
  eyebrow,
  title,
  intro,
}: {
  eyebrow: string;
  title: string;
  intro: string;
}) {
  return (
    <motion.div
      className="mx-auto mb-10 max-w-3xl text-center md:mb-14"
      initial="hidden"
      whileInView="visible"
      viewport={{ once: true, margin: "-80px" }}
      variants={containerVariants}
    >
      <motion.p className="micro-glitch-text mb-3 font-mono text-xs uppercase text-signal" data-text={eyebrow} variants={itemVariants}>
        {eyebrow}
      </motion.p>
      <motion.h2 className="micro-glitch-heading text-3xl font-semibold text-white md:text-5xl" data-text={title} variants={itemVariants}>
        {title}
      </motion.h2>
      <motion.p className="mt-4 text-base leading-8 text-haze md:text-lg" variants={itemVariants}>
        {intro}
      </motion.p>
    </motion.div>
  );
}

function GlassCard({
  children,
  className,
  delay = 0,
}: {
  children: ReactNode;
  className?: string;
  delay?: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 24 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-70px" }}
      transition={{ duration: 0.55, delay, ease: "easeOut" }}
      className={cn(
        "micro-glitch-card group relative overflow-hidden rounded-lg border border-white/10 bg-white/[0.045] p-6 shadow-glow backdrop-blur-xl transition duration-300 hover:-translate-y-1 hover:border-signal/45 hover:bg-white/[0.07]",
        className,
      )}
    >
      <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-signal/80 to-transparent opacity-60" />
      <div className="pointer-events-none absolute -right-16 -top-16 h-36 w-36 rounded-full bg-signal/10 blur-3xl transition duration-500 group-hover:bg-trace/12" />
      <div className="relative">{children}</div>
    </motion.div>
  );
}

function IconBadge({ icon: Icon, accent = "signal" }: { icon: IconType; accent?: "signal" | "volt" | "trace" }) {
  const color = accent === "volt" ? "text-volt bg-volt/10 border-volt/25" : accent === "trace" ? "text-trace bg-trace/10 border-trace/25" : "text-signal bg-signal/10 border-signal/25";
  return (
    <div className={cn("flex h-11 w-11 items-center justify-center rounded-lg border", color)}>
      <Icon size={20} strokeWidth={1.8} />
    </div>
  );
}

function AmbientGlitchLayer() {
  return (
    <div className="ambient-glitch" aria-hidden="true">
      <span className="ambient-glitch__tear ambient-glitch__tear--one" />
      <span className="ambient-glitch__tear ambient-glitch__tear--two" />
      <span className="ambient-glitch__tear ambient-glitch__tear--three" />
    </div>
  );
}

function Hero() {
  const reduceMotion = useReducedMotion();

  return (
    <section id="hero" className="relative isolate overflow-hidden px-5 pt-6">
      <CyberCanvas />
      <div className="absolute inset-0 bg-[url('/cyber-grid.png')] bg-cover bg-center opacity-28 mix-blend-screen" aria-hidden="true" />
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_10%,rgba(252,238,10,0.18),transparent_35%),linear-gradient(180deg,rgba(5,7,13,0.18),#05070d_95%)]" aria-hidden="true" />

      <nav className="relative z-20 mx-auto flex max-w-7xl items-center justify-between rounded-lg border border-white/10 bg-obsidian/55 px-4 py-3 backdrop-blur-xl">
        <a href="#hero" className="flex items-center gap-3 text-white" aria-label="Dominic Boban home">
          <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-signal/30 bg-signal/10 text-signal">
            <Shield size={18} />
          </span>
          <span className="micro-glitch-text text-sm font-semibold uppercase" data-text="Dominic Boban">Dominic Boban</span>
        </a>
        <div className="hidden items-center gap-1 md:flex">
          {navItems.map((item) => (
            <a key={item.href} href={item.href} className="glitch-control rounded-md px-3 py-2 text-sm text-haze transition hover:bg-white/5 hover:text-white">
              {item.label}
            </a>
          ))}
        </div>
        <a
          href="mailto:dominicboban@dominic-boban.com"
          className="inline-flex h-10 items-center justify-center gap-2 rounded-lg border border-white/15 bg-white/5 px-3 text-sm font-medium text-white transition hover:border-signal/50 hover:bg-signal/10"
        >
          <Mail size={16} />
          <span className="hidden sm:inline">Email</span>
        </a>
      </nav>

      <div className="relative z-10 mx-auto grid min-h-[84svh] max-w-7xl items-center gap-10 py-16 lg:grid-cols-[1.1fr_0.9fr] lg:py-20">
        <motion.div initial="hidden" animate="visible" variants={containerVariants}>
          <motion.div className="micro-glitch-card mb-5 inline-flex items-center gap-2 rounded-lg border border-signal/20 bg-signal/10 px-3 py-2 font-mono text-xs uppercase text-signal" variants={itemVariants}>
            <Sparkles size={14} />
            London-based penetration tester
          </motion.div>
          <motion.h1 className="micro-glitch-heading max-w-5xl text-5xl font-semibold leading-[1.02] text-white sm:text-6xl lg:text-7xl" data-text="Offensive Security. Defensive Thinking. Real-World Impact." variants={itemVariants}>
            Offensive Security. Defensive Thinking. Real-World Impact.
          </motion.h1>
          <motion.p className="mt-6 max-w-2xl text-lg leading-8 text-haze md:text-xl" variants={itemVariants}>
            Dominic Boban is a Cyber Security Penetration Tester with over two years of experience improving security through penetration testing, SIEM monitoring, CVE automation, dark web monitoring, and vulnerability detection.
          </motion.p>
          <motion.div className="mt-8 flex flex-col gap-3 sm:flex-row" variants={itemVariants}>
            <a
              href="#projects"
              className="glitch-control inline-flex h-12 items-center justify-center gap-2 rounded-lg bg-signal px-5 text-sm font-semibold text-obsidian transition hover:bg-white"
            >
              View Projects
              <ChevronRight size={17} />
            </a>
            <a
              href="/Dominic_Boban_CV.pdf"
              download
              className="glitch-control inline-flex h-12 items-center justify-center gap-2 rounded-lg border border-white/15 bg-white/5 px-5 text-sm font-semibold text-white transition hover:border-volt/50 hover:bg-volt/10"
            >
              <Download size={17} />
              Download CV
            </a>
            <a
              href="#contact"
              className="glitch-control inline-flex h-12 items-center justify-center gap-2 rounded-lg border border-white/15 bg-white/5 px-5 text-sm font-semibold text-white transition hover:border-trace/50 hover:bg-trace/10"
            >
              Contact Me
            </a>
          </motion.div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, x: 32 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.75, delay: 0.24 }}
          className="relative"
        >
          <div className="absolute -inset-6 rounded-lg bg-gradient-to-br from-signal/18 via-trace/10 to-volt/12 blur-3xl" aria-hidden="true" />
          <div className="relative overflow-hidden rounded-lg border border-white/10 bg-obsidian/70 shadow-2xl shadow-signal/10 backdrop-blur-2xl">
            <div className="flex items-center gap-2 border-b border-white/10 px-4 py-3">
              <span className="h-3 w-3 rounded-full bg-trace" />
              <span className="h-3 w-3 rounded-full bg-volt" />
              <span className="h-3 w-3 rounded-full bg-signal" />
              <span className="ml-2 font-mono text-xs text-haze">ambient-threat-console</span>
            </div>
            <div className="space-y-4 p-5 font-mono text-sm leading-7">
              {terminalLines.map((line, index) => (
                <motion.div
                  key={line}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: reduceMotion ? 0 : 0.4 + index * 0.16 }}
              className={cn("micro-glitch-text", line.startsWith("$") ? "text-signal" : "text-haze")}
              data-text={line}
                >
                  {line}
                </motion.div>
              ))}
            </div>
            <div className="grid grid-cols-2 border-t border-white/10">
              {profileStats.map((stat) => (
                <div key={stat.label} className="border-r border-t border-white/10 p-4 last:border-r-0 sm:p-5">
                  <div className="text-2xl font-semibold text-white">{stat.value}</div>
                  <div className="mt-1 text-xs uppercase leading-5 text-haze">{stat.label}</div>
                </div>
              ))}
            </div>
          </div>
        </motion.div>
      </div>

      <div className="relative z-10 mx-auto -mt-8 max-w-7xl pb-8">
        <a href="#about" className="inline-flex items-center gap-2 text-sm text-haze transition hover:text-white">
          <ArrowDown size={16} />
          Scroll to profile
        </a>
      </div>
    </section>
  );
}

function About() {
  return (
    <section id="about" className="relative px-5 py-20 md:py-28">
      <div className="mx-auto max-w-7xl">
        <SectionHeader
          eyebrow="Profile"
          title="A security operator with offensive depth and executive clarity."
          intro="Dominic combines hands-on penetration testing, SOC discipline, automation, and calm operational leadership to help teams discover, understand, and remediate security risk."
        />
        <div className="grid gap-5 lg:grid-cols-[0.95fr_1.05fr]">
          <GlassCard className="min-h-full">
            <div className="mb-6 flex items-center gap-3">
              <IconBadge icon={GraduationCap} />
              <div>
                <p className="font-mono text-xs uppercase text-signal">Foundation</p>
                <h3 className="text-2xl font-semibold text-white">First-Class Cyber Security graduate</h3>
              </div>
            </div>
            <p className="leading-8 text-haze">
              Based in London / Ealing, Dominic brings a practical security mindset shaped by academic excellence, penetration testing delivery, SOC operations, and frontline leadership. His work focuses on finding real weaknesses, validating risk, and turning evidence into clear remediation.
            </p>
          </GlassCard>
          <div className="grid gap-5 sm:grid-cols-2">
            {[
              ["Current Role", "Penetration Tester at Baseel Partners, delivering web, infrastructure, SIEM, OSINT, and reporting work."],
              ["SOC Background", "Former SOC Level 1 Intern with experience in triage, IOC enrichment, log analysis, and escalation notes."],
              ["Leadership Range", "Retail Supervisor experience built communication, team leadership, scheduling, and operational discipline."],
              ["Recognition", "Top 800 Hack The Box ranking and Microsoft Hall of Fame recognition for security contributions."],
            ].map(([title, body], index) => (
              <GlassCard key={title} delay={index * 0.06}>
                <h3 className="text-lg font-semibold text-white">{title}</h3>
                <p className="mt-3 leading-7 text-haze">{body}</p>
              </GlassCard>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

function Skills() {
  return (
    <section id="skills" className="px-5 py-20 md:py-28">
      <div className="mx-auto max-w-7xl">
        <SectionHeader
          eyebrow="Technical Stack"
          title="Tooling shaped around finding risk and strengthening detection."
          intro="A blended skillset across offensive testing, cloud review, scripting, SIEM workflows, threat intelligence, and security frameworks."
        />
        <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-3">
          {skillGroups.map((group, index) => (
            <GlassCard key={group.title} delay={index * 0.04} className={group.title === "Testing Areas" ? "xl:col-span-2" : ""}>
              <div className="mb-5 flex items-center justify-between gap-4">
                <div>
                  <p className="font-mono text-xs uppercase text-haze">Capability cluster</p>
                  <h3 className="mt-1 text-xl font-semibold text-white">{group.title}</h3>
                </div>
                <IconBadge icon={group.icon} accent={group.accent as "signal" | "volt" | "trace"} />
              </div>
              <div className="flex flex-wrap gap-2">
                {group.items.map((item) => (
                  <span key={item} className="rounded-md border border-white/10 bg-white/[0.04] px-3 py-2 text-sm text-haze transition group-hover:border-white/20 group-hover:text-white">
                    {item}
                  </span>
                ))}
              </div>
            </GlassCard>
          ))}
        </div>
      </div>
    </section>
  );
}

function Experience() {
  return (
    <section id="experience" className="px-5 py-20 md:py-28">
      <div className="mx-auto max-w-7xl">
        <SectionHeader
          eyebrow="Experience"
          title="A timeline built across red-team practice, SOC visibility, and operational leadership."
          intro="Dominic's path pairs offensive validation with the defensive systems that make findings measurable and actionable."
        />
        <div className="relative mx-auto max-w-5xl">
          <div className="absolute left-4 top-0 hidden h-full w-px bg-gradient-to-b from-signal via-white/20 to-trace md:block" />
          <div className="space-y-6">
            {experience.map((item, index) => (
              <motion.article
                key={item.company}
                initial={{ opacity: 0, y: 26 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: "-80px" }}
                transition={{ duration: 0.55, delay: index * 0.08 }}
                className="relative md:pl-14"
              >
                <div className="absolute left-0 top-7 hidden h-8 w-8 items-center justify-center rounded-lg border border-signal/35 bg-obsidian text-signal shadow-glow md:flex">
                  <item.icon size={16} />
                </div>
                <div className="rounded-lg border border-white/10 bg-white/[0.045] p-6 backdrop-blur-xl transition hover:border-signal/40 hover:bg-white/[0.07]">
                  <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
                    <div>
                      <p className="font-mono text-xs uppercase text-signal">{item.period}</p>
                      <h3 className="mt-2 text-2xl font-semibold text-white">{item.role}</h3>
                      <p className="mt-1 text-haze">{item.company} - {item.location}</p>
                    </div>
                    <span className="inline-flex w-fit items-center gap-2 rounded-md border border-white/10 bg-white/5 px-3 py-2 font-mono text-xs uppercase text-haze">
                      <Terminal size={14} />
                      verified impact
                    </span>
                  </div>
                  <ul className="mt-6 grid gap-3">
                    {item.points.map((point) => (
                      <li key={point} className="flex gap-3 leading-7 text-haze">
                        <span className="mt-3 h-1.5 w-1.5 shrink-0 rounded-full bg-signal" />
                        <span>{point}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </motion.article>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

function Projects() {
  return (
    <section id="projects" className="px-5 py-20 md:py-28">
      <div className="mx-auto max-w-7xl">
        <SectionHeader
          eyebrow="Selected Work"
          title="Portfolio-safe case studies from real security workflows."
          intro="Sanitized projects show Dominic's approach to automation, monitoring, vulnerability management, and stakeholder-ready reporting without exposing sensitive operational details."
        />
        <div className="grid gap-5 md:grid-cols-2">
          {projects.map((project, index) => (
            <GlassCard key={project.title} delay={index * 0.06}>
              <div className="flex items-start justify-between gap-5">
                <IconBadge icon={project.icon} accent={index % 2 === 0 ? "signal" : "trace"} />
                <p className="rounded-md border border-volt/20 bg-volt/10 px-3 py-2 font-mono text-xs uppercase text-volt">
                  {project.metric}
                </p>
              </div>
              <p className="mt-7 font-mono text-xs uppercase text-haze">{project.kicker}</p>
              <h3 className="mt-2 text-2xl font-semibold text-white">{project.title}</h3>
              <p className="mt-4 leading-8 text-haze">{project.body}</p>
            </GlassCard>
          ))}
        </div>
      </div>
    </section>
  );
}

function Achievements() {
  return (
    <section id="achievements" className="px-5 py-20 md:py-28">
      <div className="mx-auto max-w-7xl">
        <SectionHeader
          eyebrow="Achievements"
          title="Proof points that translate skill into measurable signal."
          intro="Recognition and security engineering outcomes that reflect both offensive capability and defensive improvement."
        />
        <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-5">
          {achievements.map((achievement, index) => (
            <GlassCard key={achievement.title} delay={index * 0.05} className="xl:min-h-[270px]">
              <div className="mb-8 flex items-center justify-between">
                <IconBadge icon={achievement.icon} accent={index % 3 === 0 ? "volt" : index % 3 === 1 ? "trace" : "signal"} />
                <span className="font-mono text-xs text-white/35">0{index + 1}</span>
              </div>
              <h3 className="text-xl font-semibold text-white">{achievement.title}</h3>
              <p className="mt-4 leading-7 text-haze">{achievement.detail}</p>
            </GlassCard>
          ))}
        </div>
      </div>
    </section>
  );
}

function Certifications() {
  return (
    <section id="certifications" className="px-5 py-20 md:py-28">
      <div className="mx-auto max-w-7xl">
        <SectionHeader
          eyebrow="Certifications"
          title="Structured learning across penetration testing, SOC, and red-team foundations."
          intro="Certifications reinforce the practical work with industry-recognised security training and assessment methods."
        />
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
          {certifications.map((cert, index) => (
            <GlassCard key={cert.name} delay={index * 0.04}>
              <div className="mb-6 flex items-center justify-between gap-3">
                <BadgeCheck className={cert.status === "In Progress" ? "text-volt" : "text-signal"} size={22} />
                <span className="rounded-md border border-white/10 px-2 py-1 font-mono text-xs text-haze">{cert.date}</span>
              </div>
              <h3 className="text-lg font-semibold text-white">{cert.name}</h3>
              <p className="mt-3 text-sm leading-6 text-haze">{cert.issuer}</p>
              <p className="mt-5 font-mono text-xs uppercase text-signal">{cert.status}</p>
            </GlassCard>
          ))}
        </div>
      </div>
    </section>
  );
}

function Contact() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState("");
  const [formStatus, setFormStatus] = useState<"idle" | "sending" | "success" | "error">("idle");

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setFormStatus("sending");

    const senderName = name.trim();
    const senderEmail = email.trim();
    const senderMessage = message.trim();
    const formData = new FormData();
    formData.append("from_name", "Dominic Boban Portfolio");
    formData.append("subject", `Portfolio enquiry from ${senderName || "a portfolio visitor"}`);
    formData.append("name", senderName);
    formData.append("email", senderEmail);
    formData.append("replyto", senderEmail);
    formData.append("message", senderMessage);

    try {
      const response = await fetch("/api/contact", {
        method: "POST",
        body: formData,
      });

      const result = (await response.json().catch(() => null)) as { success?: boolean } | null;

      if (!response.ok || result?.success === false) {
        throw new Error("Web3Forms submission failed");
      }

      setName("");
      setEmail("");
      setMessage("");
      setFormStatus("success");
    } catch {
      setFormStatus("error");
    }
  };

  return (
    <section id="contact" className="px-5 py-20 md:py-28">
      <div className="mx-auto max-w-7xl">
        <SectionHeader
          eyebrow="Contact"
          title="Open a secure channel."
          intro="For penetration testing, vulnerability validation, SIEM monitoring, and threat intelligence work, contact Dominic directly."
        />
        <div className="grid gap-5 lg:grid-cols-[0.9fr_1.1fr]">
          <GlassCard>
            <div className="space-y-4">
              <a href="mailto:dominicboban@dominic-boban.com" className="flex items-center gap-4 rounded-lg border border-white/10 bg-white/[0.035] p-4 text-haze transition hover:border-signal/40 hover:text-white">
                <IconBadge icon={Mail} />
                <span>dominicboban@dominic-boban.com</span>
              </a>
              <a href="https://www.linkedin.com/in/dominic-boban-2b6823193/" target="_blank" rel="noreferrer" className="flex items-center gap-4 rounded-lg border border-white/10 bg-white/[0.035] p-4 text-haze transition hover:border-signal/40 hover:text-white">
                <IconBadge icon={Linkedin} accent="volt" />
                <span>LinkedIn</span>
                <ExternalLink className="ml-auto" size={16} />
              </a>
              <a href="https://github.com/dom4570" target="_blank" rel="noreferrer" className="flex items-center gap-4 rounded-lg border border-white/10 bg-white/[0.035] p-4 text-haze transition hover:border-signal/40 hover:text-white">
                <IconBadge icon={Github} accent="trace" />
                <span>GitHub</span>
                <ExternalLink className="ml-auto" size={16} />
              </a>
              <div className="flex items-center gap-4 rounded-lg border border-white/10 bg-white/[0.035] p-4 text-haze">
                <IconBadge icon={MapPin} />
                <span>London / Ealing</span>
              </div>
            </div>
          </GlassCard>

          <motion.form
            onSubmit={submit}
            name="contact"
            initial={{ opacity: 0, y: 24 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-70px" }}
            transition={{ duration: 0.55 }}
            className="overflow-hidden rounded-lg border border-white/10 bg-obsidian/70 shadow-trace backdrop-blur-xl"
          >
            <div className="flex items-center gap-2 border-b border-white/10 px-4 py-3">
              <span className="h-3 w-3 rounded-full bg-trace" />
              <span className="h-3 w-3 rounded-full bg-volt" />
              <span className="h-3 w-3 rounded-full bg-signal" />
              <span className="ml-2 font-mono text-xs text-haze">contact-session.sh</span>
            </div>
            <div className="grid gap-5 p-5 md:p-6">
              <TerminalLabel label="$ whoami">
                <input name="name" value={name} onChange={(event) => setName(event.target.value)} className="terminal-input" placeholder="Your name" required />
              </TerminalLabel>
              <TerminalLabel label="$ reply_to">
                <input name="email" value={email} onChange={(event) => setEmail(event.target.value)} type="email" className="terminal-input" placeholder="you@example.com" required />
              </TerminalLabel>
              <TerminalLabel label="$ message">
                <textarea name="message" value={message} onChange={(event) => setMessage(event.target.value)} className="terminal-input min-h-36 resize-y" placeholder="Type your message..." required />
              </TerminalLabel>
              {formStatus === "success" && (
                <p className="rounded-md border border-signal/30 bg-signal/10 px-4 py-3 font-mono text-xs uppercase leading-5 text-signal">
                  Message transmitted. Dominic will get back to you shortly.
                </p>
              )}
              {formStatus === "error" && (
                <p className="rounded-md border border-trace/40 bg-trace/10 px-4 py-3 font-mono text-xs uppercase leading-5 text-trace">
                  Transmission failed. Email dominicboban@dominic-boban.com directly.
                </p>
              )}
              <button type="submit" disabled={formStatus === "sending"} className="inline-flex h-12 items-center justify-center gap-2 rounded-lg bg-signal px-5 text-sm font-semibold text-obsidian transition hover:bg-white disabled:cursor-not-allowed disabled:opacity-70">
                <Mail size={17} />
                {formStatus === "sending" ? "Transmitting..." : "Send Message"}
              </button>
            </div>
          </motion.form>
        </div>
      </div>
    </section>
  );
}

function TerminalLabel({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="grid gap-2">
      <span className="micro-glitch-text font-mono text-xs uppercase text-signal" data-text={label}>{label}</span>
      {children}
    </label>
  );
}

export default function App() {
  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    let timeoutId = 0;
    let releaseId = 0;

    const triggerJitter = () => {
      const delay = 1800 + Math.random() * 4200;

      timeoutId = window.setTimeout(() => {
        document.body.classList.add("is-signal-jitter");

        releaseId = window.setTimeout(() => {
          document.body.classList.remove("is-signal-jitter");
          triggerJitter();
        }, 110 + Math.random() * 90);
      }, delay);
    };

    triggerJitter();

    return () => {
      window.clearTimeout(timeoutId);
      window.clearTimeout(releaseId);
      document.body.classList.remove("is-signal-jitter");
    };
  }, []);

  useEffect(() => {
    const scrollToHash = () => {
      const hash = window.location.hash;
      if (!hash) return;

      window.requestAnimationFrame(() => {
        document.querySelector(hash)?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    };

    scrollToHash();
    window.addEventListener("hashchange", scrollToHash);

    return () => window.removeEventListener("hashchange", scrollToHash);
  }, []);

  return (
    <>
      <main className="min-h-screen overflow-x-hidden bg-obsidian text-white">
        <AmbientGlitchLayer />
        <Hero />
        <About />
        <Skills />
        <Experience />
        <Projects />
        <Achievements />
        <Certifications />
        <Contact />
        <footer className="border-t border-white/10 px-5 py-8">
          <div className="mx-auto flex max-w-7xl flex-col gap-3 text-sm text-haze md:flex-row md:items-center md:justify-between">
            <p>Dominic Boban - Cyber Security Penetration Tester</p>
            <p className="font-mono text-xs uppercase text-white/45">Offensive security / defensive signal / real-world impact</p>
          </div>
        </footer>
      </main>
    </>
  );
}
