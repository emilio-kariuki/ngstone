import { buttonVariants } from "@/components/ui/button";
import { TerminalWindow } from "@/components/terminal-window";
import { cn } from "@/lib/utils";

export function Hero() {
  return (
    <section className="relative overflow-hidden bg-grain">
      <div className="pointer-events-none absolute inset-0 -z-10 bg-stone-grid [mask-image:linear-gradient(to_bottom,black,transparent_75%)]" />

      <div className="mx-auto max-w-6xl px-6 pt-24 pb-28 sm:pt-32 sm:pb-36">
        <div className="mx-auto max-w-3xl text-center">
          <h1
            className="animate-fade-up text-balance font-display text-4xl leading-[1.08] font-medium tracking-tight sm:text-5xl md:text-6xl"
            style={{ animationDelay: "0.05s" }}
          >
            Your own tunnel.
            <br className="hidden sm:block" /> Your own domain.
          </h1>

          <p
            className="animate-fade-up mx-auto mt-6 max-w-xl text-balance text-lg text-muted-foreground"
            style={{ animationDelay: "0.2s" }}
          >
            A self-hosted ngrok replacement. Run the edge on your own VPS,
            point your own domain at it, and keep every request off someone
            else&rsquo;s servers.
          </p>

          <div
            className="animate-fade-up mt-9 flex flex-col items-center justify-center gap-3 sm:flex-row"
            style={{ animationDelay: "0.32s" }}
          >
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

        <div
          className="animate-fade-up relative mx-auto mt-16 max-w-2xl"
          style={{ animationDelay: "0.46s" }}
        >
          <div
            aria-hidden
            className="ember-glow pointer-events-none absolute -inset-x-12 -inset-y-20 -z-10 blur-2xl"
          />
          <TerminalWindow>
            <div className="flex items-center gap-2 text-muted-foreground">
              <span className="select-none">$</span>
              <span className="text-foreground">ngstone port 3000</span>
            </div>
            <div className="mt-3 flex items-center gap-2">
              <span className="text-primary">&rarr;</span>
              <span className="text-foreground">
                https://amber-fox-42.yourdomain.com
              </span>
              <span
                aria-hidden
                className="animate-blink h-4 w-2 translate-y-px bg-primary"
              />
            </div>
          </TerminalWindow>
        </div>
      </div>
    </section>
  );
}
