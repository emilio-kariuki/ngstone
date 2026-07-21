import { Features } from "@/components/features";
import { FinalCta } from "@/components/final-cta";
import { Hero } from "@/components/hero";
import { HowItWorks } from "@/components/how-it-works";
import { Inspector } from "@/components/inspector";
import { Quickstart } from "@/components/quickstart";
import { SiteFooter } from "@/components/site-footer";
import { SiteHeader } from "@/components/site-header";
import { TrustBar } from "@/components/trust-bar";

export default function Home() {
  return (
    <div className="flex flex-1 flex-col">
      <SiteHeader />
      <main className="flex-1">
        <Hero />
        <TrustBar />
        <Features />
        <HowItWorks />
        <Inspector />
        <Quickstart />
        <FinalCta />
      </main>
      <SiteFooter />
    </div>
  );
}
