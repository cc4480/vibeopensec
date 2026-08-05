import { Link } from "wouter";
import { motion } from "framer-motion";
import { useTranslation } from "react-i18next";
import {
  ShieldAlert, Key, Globe, CheckCircle2, ArrowRight, Activity,
  Code2, Zap, Bell, Search, Bot, FileKey, Database, Network,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface TitleDesc {
  title: string;
  desc: string;
}

interface TierCopy {
  title: string;
  desc: string;
  features: string[];
  cta: string;
}

const PROBLEM_PRESENTATION = [
  { icon: Key, color: "text-red-400", bg: "bg-red-400/10" },
  { icon: ShieldAlert, color: "text-orange-400", bg: "bg-orange-400/10" },
  { icon: Globe, color: "text-yellow-400", bg: "bg-yellow-400/10" },
];

const STEP_PRESENTATION = [
  { step: 1, icon: Code2 },
  { step: 2, icon: Zap },
  { step: 3, icon: CheckCircle2 },
];

const AI_BUILDER_PRESENTATION = [
  { icon: Database, color: "text-red-400", bg: "bg-red-400/10" },
  { icon: FileKey, color: "text-orange-400", bg: "bg-orange-400/10" },
  { icon: Bot, color: "text-blue-400", bg: "bg-blue-400/10" },
  { icon: Network, color: "text-purple-400", bg: "bg-purple-400/10" },
];

const OWASP_PRESENTATION = [
  { tag: "A01", tagColor: "text-primary", tagBg: "bg-primary/10 border-primary/20" },
  { tag: "A02", tagColor: "text-primary", tagBg: "bg-primary/10 border-primary/20" },
  { tag: "A03", tagColor: "text-primary", tagBg: "bg-primary/10 border-primary/20" },
  { tag: "A05", tagColor: "text-primary", tagBg: "bg-primary/10 border-primary/20" },
  { tag: "A06", tagColor: "text-primary", tagBg: "bg-primary/10 border-primary/20" },
  { tag: "A07", tagColor: "text-primary", tagBg: "bg-primary/10 border-primary/20" },
  { tag: "Files", tagColor: "text-orange-400", tagBg: "bg-orange-400/10 border-orange-400/20" },
  { tag: "DNS", tagColor: "text-blue-400", tagBg: "bg-blue-400/10 border-blue-400/20" },
  { tag: "Crawl", tagColor: "text-purple-400", tagBg: "bg-purple-400/10 border-purple-400/20" },
];

const PRICING_PRESENTATION = [
  { icon: Search, href: "/scan", color: "text-primary", bg: "bg-primary/10", border: "" },
  { icon: Bot, href: "/scan", color: "text-primary", bg: "bg-primary/10", border: "border-primary/50 shadow-[0_0_30px_rgba(20,184,120,0.1)]", popular: true },
  { icon: Bell, href: "/monitor", color: "text-indigo-400", bg: "bg-indigo-400/10", border: "border-indigo-500/30" },
];

export default function LandingPage() {
  const { t } = useTranslation();

  const containerVariants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: 0.1 }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 20 },
    show: { opacity: 1, y: 0, transition: { type: "spring" as const, stiffness: 300, damping: 24 } }
  };

  const problemItems = t("landing.problem.items", { returnObjects: true }) as TitleDesc[];
  const steps = t("landing.howItWorks.steps", { returnObjects: true }) as TitleDesc[];
  const aiBuilderCards = t("landing.aiBuilder.cards", { returnObjects: true }) as TitleDesc[];
  const owaspItems = t("landing.owasp.items", { returnObjects: true }) as TitleDesc[];
  const pricingTiers = t("landing.pricing.tiers", { returnObjects: true }) as TierCopy[];

  return (
    <div className="flex flex-col gap-24 lg:gap-32">
      {/* Hero Section */}
      <section className="relative pt-12 pb-20 lg:pt-24 lg:pb-32 overflow-hidden">
        <div className="absolute inset-0 z-0">
          <img
            src={`${import.meta.env.BASE_URL}images/hero-bg.png`}
            alt="Cyber security background"
            className="w-full h-full object-cover opacity-30 mix-blend-screen"
          />
          <div className="absolute inset-0 bg-gradient-to-b from-background/10 via-background/80 to-background" />
        </div>

        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
          <motion.div
            variants={containerVariants}
            initial="hidden"
            animate="show"
            className="max-w-3xl mx-auto text-center flex flex-col items-center"
          >
            <motion.div variants={itemVariants} className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 text-primary text-sm font-medium mb-8">
              <Activity className="w-4 h-4" />
              <span>{t("landing.hero.badge")}</span>
            </motion.div>

            <motion.h1 variants={itemVariants} className="text-5xl md:text-6xl lg:text-7xl font-bold tracking-tight mb-6">
              {t("landing.hero.titleLine1")} <br />
              <span className="text-gradient-primary">{t("landing.hero.titleLine2")}</span>
            </motion.h1>

            <motion.p variants={itemVariants} className="text-lg md:text-xl text-muted-foreground mb-10 max-w-2xl">
              {t("landing.hero.subtitle")}
            </motion.p>

            <motion.div variants={itemVariants} className="flex flex-col sm:flex-row items-center gap-4 w-full sm:w-auto">
              <Link
                href="/scan"
                className="w-full sm:w-auto px-8 py-4 bg-primary text-primary-foreground text-lg font-bold rounded-xl shadow-[0_0_30px_rgba(20,184,120,0.25)] hover:shadow-[0_0_40px_rgba(20,184,120,0.4)] hover:-translate-y-1 transition-all duration-300 flex items-center justify-center gap-2"
              >
                {t("landing.hero.ctaScan")} <ArrowRight className="w-5 h-5" />
              </Link>
              <a
                href="#pricing"
                className="w-full sm:w-auto px-8 py-4 bg-secondary text-foreground text-lg font-semibold rounded-xl border border-white/5 hover:bg-secondary/80 transition-all duration-300 text-center"
              >
                {t("landing.hero.ctaPricing")}
              </a>
            </motion.div>

            <motion.p variants={itemVariants} className="flex items-center gap-2 text-sm text-muted-foreground mt-6">
              <CheckCircle2 className="w-4 h-4 text-primary shrink-0" />
              {t("landing.hero.trustClaim")}
            </motion.p>
          </motion.div>
        </div>
      </section>

      {/* Problem Section */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="text-3xl md:text-4xl font-bold mb-4">{t("landing.problem.title")}</h2>
          <p className="text-muted-foreground max-w-2xl mx-auto">{t("landing.problem.subtitle")}</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {problemItems.map((item, i) => {
            const presentation = PROBLEM_PRESENTATION[i]!;
            return (
              <div key={i} className="glass-card p-8 rounded-2xl">
                <div className={cn("w-12 h-12 rounded-xl flex items-center justify-center mb-6", presentation.bg, presentation.color)}>
                  <presentation.icon className="w-6 h-6" />
                </div>
                <h3 className="text-xl font-bold mb-3">{item.title}</h3>
                <p className="text-muted-foreground">{item.desc}</p>
              </div>
            );
          })}
        </div>
      </section>

      {/* How it works */}
      <section className="bg-card/30 border-y border-white/5 py-24">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">{t("landing.howItWorks.title")}</h2>
            <p className="text-muted-foreground">{t("landing.howItWorks.subtitle")}</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-12 relative">
            <div className="hidden md:block absolute top-12 left-[15%] right-[15%] h-0.5 bg-gradient-to-r from-primary/0 via-primary/30 to-primary/0" />

            {steps.map((item, i) => {
              const presentation = STEP_PRESENTATION[i]!;
              return (
                <div key={i} className="relative flex flex-col items-center text-center">
                  <div className="w-24 h-24 rounded-full bg-background border-2 border-primary/30 flex items-center justify-center mb-6 shadow-[0_0_20px_rgba(20,184,120,0.1)] relative z-10">
                    <presentation.icon className="w-10 h-10 text-primary" />
                    <div className="absolute -top-2 -right-2 w-8 h-8 rounded-full bg-primary text-background font-bold flex items-center justify-center border-4 border-background">
                      {presentation.step}
                    </div>
                  </div>
                  <h3 className="text-xl font-bold mb-3">{item.title}</h3>
                  <p className="text-muted-foreground">{item.desc}</p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* AI-Builder Callout Section */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="glass-panel rounded-3xl p-10 lg:p-16 border-primary/20 bg-primary/5 relative overflow-hidden">
          <div className="absolute top-0 right-0 w-96 h-96 bg-primary/5 rounded-full blur-3xl -translate-y-1/2 translate-x-1/2 pointer-events-none" />
          <div className="relative z-10 grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            <div>
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-primary/10 border border-primary/20 text-primary text-xs font-semibold mb-6 uppercase tracking-wider">
                <Bot className="w-3.5 h-3.5" /> {t("landing.aiBuilder.eyebrow")}
              </div>
              <h2 className="text-3xl md:text-4xl font-bold mb-5">
                {t("landing.aiBuilder.titleLine1")}<br />
                <span className="text-gradient-primary">{t("landing.aiBuilder.titleLine2")}</span>
              </h2>
              <p className="text-muted-foreground mb-8 text-lg leading-relaxed">
                {t("landing.aiBuilder.subtitle")}
              </p>
              <Link
                href="/scan"
                className="inline-flex items-center gap-2 px-6 py-3 bg-primary text-primary-foreground font-bold rounded-xl hover:shadow-[0_0_20px_rgba(20,184,120,0.4)] transition-all"
              >
                {t("landing.aiBuilder.cta")} <ArrowRight className="w-4 h-4" />
              </Link>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {aiBuilderCards.map((item, i) => {
                const presentation = AI_BUILDER_PRESENTATION[i]!;
                return (
                  <div key={i} className="glass-card p-5 rounded-2xl flex flex-col gap-3">
                    <div className={cn("w-10 h-10 rounded-xl flex items-center justify-center shrink-0", presentation.bg, presentation.color)}>
                      <presentation.icon className="w-5 h-5" />
                    </div>
                    <div>
                      <h4 className="font-semibold text-sm mb-1">{item.title}</h4>
                      <p className="text-xs text-muted-foreground leading-relaxed">{item.desc}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </section>

      {/* OWASP Coverage Section */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-primary/10 border border-primary/20 text-primary text-xs font-semibold mb-4 uppercase tracking-wider">
            <Activity className="w-3.5 h-3.5" /> {t("landing.owasp.eyebrow")}
          </div>
          <h2 className="text-3xl md:text-4xl font-bold mb-4">{t("landing.owasp.title")}</h2>
          <p className="text-muted-foreground max-w-2xl mx-auto">
            {t("landing.owasp.subtitle")}
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {owaspItems.map((item, i) => {
            const presentation = OWASP_PRESENTATION[i]!;
            return (
              <div key={presentation.tag} className="glass-card p-6 rounded-2xl flex gap-4 group hover:border-primary/30 transition-colors">
                <div className={cn("shrink-0 w-10 h-10 rounded-lg border flex items-center justify-center", presentation.tagBg)}>
                  <span className={cn("font-mono text-xs font-bold", presentation.tagColor)}>{presentation.tag}</span>
                </div>
                <div>
                  <h3 className="font-semibold text-foreground mb-1">{item.title}</h3>
                  <p className="text-sm text-muted-foreground leading-relaxed">{item.desc}</p>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* What you get */}
      <section id="pricing" className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-primary/10 border border-primary/20 text-primary text-xs font-semibold mb-4 uppercase tracking-wider">
            <Zap className="w-3.5 h-3.5" /> {t("landing.pricing.eyebrow")}
          </div>
          <h2 className="text-3xl md:text-4xl font-bold mb-4">{t("landing.pricing.title")}</h2>
          <p className="text-muted-foreground max-w-2xl mx-auto">{t("landing.pricing.subtitle")}</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-4xl mx-auto">
          {pricingTiers.map((item, i) => {
            const presentation = PRICING_PRESENTATION[i]!;
            return (
              <div key={i} className={cn("glass-panel p-8 rounded-2xl flex flex-col relative", presentation.border)}>
                {presentation.popular && (
                  <div className="absolute top-0 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-primary text-primary-foreground px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider">
                    {t("landing.pricing.mostPopular")}
                  </div>
                )}
                <div className={cn("w-12 h-12 rounded-xl flex items-center justify-center mb-5", presentation.bg, presentation.color)}>
                  <presentation.icon className="w-6 h-6" />
                </div>
                <h3 className="text-xl font-bold mb-2">{item.title}</h3>
                <p className="text-sm text-muted-foreground pb-5 border-b border-white/10 mb-5">{item.desc}</p>
                <ul className="flex flex-col gap-2.5 mb-8 flex-1">
                  {item.features.map((feat, j) => (
                    <li key={j} className="flex items-start gap-2 text-sm">
                      <CheckCircle2 className={cn("w-4 h-4 shrink-0 mt-0.5", presentation.color)} />
                      <span>{feat}</span>
                    </li>
                  ))}
                </ul>
                <Link
                  href={presentation.href}
                  className={cn(
                    "w-full py-3 rounded-xl font-bold transition-all text-center block",
                    presentation.popular
                      ? "bg-primary text-primary-foreground hover:shadow-[0_0_20px_rgba(20,184,120,0.4)]"
                      : presentation.href === "/monitor"
                      ? "bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 hover:bg-indigo-500/30"
                      : "bg-secondary text-foreground hover:bg-white/10",
                  )}
                >
                  {item.cta}
                </Link>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}
