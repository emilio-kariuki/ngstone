import { Gauge, Globe, ServerCog, ShieldOff } from "lucide-react";

import { Separator } from "@/components/ui/separator";

const ITEMS = [
  {
    icon: ServerCog,
    label: "Self-hosted, on your own VPS",
  },
  {
    icon: Globe,
    label: "Your domain, not a shared one",
  },
  {
    icon: Gauge,
    label: "No request caps, no seat pricing",
  },
  {
    icon: ShieldOff,
    label: "No third party sees your traffic",
  },
];

export function TrustBar() {
  return (
    <section className="border-y border-border bg-card/40">
      <div className="mx-auto max-w-6xl px-6 py-8">
        <div className="flex flex-col divide-y divide-border sm:flex-row sm:flex-wrap sm:items-center sm:justify-center sm:gap-x-10 sm:divide-y-0">
          {ITEMS.map((item, index) => (
            <div key={item.label} className="flex items-center gap-4">
              <div className="flex items-center gap-2.5 py-3 sm:py-0">
                <div className="rounded-md bg-primary/10 p-1.5 text-primary [&>svg]:h-4 [&>svg]:w-4">
                  <item.icon />
                </div>
                <span className="text-sm text-muted-foreground">
                  {item.label}
                </span>
              </div>
              {index < ITEMS.length - 1 && (
                <Separator
                  orientation="vertical"
                  className="hidden h-4 sm:block"
                />
              )}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
