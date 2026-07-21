import { buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export function FinalCta() {
  return (
    <section className="relative overflow-hidden border-t border-border">
      <div className="ember-glow pointer-events-none absolute inset-0 -z-10 opacity-70" />
      <div className="mx-auto max-w-3xl px-6 py-24 text-center sm:py-28">
        <h2 className="font-display text-3xl font-medium tracking-tight sm:text-4xl">
          Stop renting your own tunnel.
        </h2>
        <p className="mt-4 text-balance text-muted-foreground">
          Two binaries, one domain you already own. Point ngstoned at your
          VPS, point ngstone at your laptop, and you&rsquo;re done.
        </p>
        <div className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
          <a
            href="#quickstart"
            className={cn(buttonVariants({ size: "lg" }), "px-6")}
          >
            Get Started
          </a>
          <a
            href="#"
            className={cn(
              buttonVariants({ variant: "outline", size: "lg" }),
              "px-6"
            )}
          >
            View on GitHub
          </a>
        </div>
      </div>
    </section>
  );
}
