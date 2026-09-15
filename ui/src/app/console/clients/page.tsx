"use client";

import { useSearchParams } from "next/navigation";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { ClientDetail } from "@/components/console/clients/detail";
import { RevealModal, type Revealed } from "@/components/console/clients/reveal";
import { ClientsTable } from "@/components/console/clients/table";
import { ClientWizard } from "@/components/console/clients/wizard";
import { Spinner } from "@/components/ui";
import { clientHref, type RevealView } from "@/lib/console/clients";
import { useConsoleTenant } from "@/lib/console/tenant";

/** `/console/clients/`: the table, or one client when `?client=` is set. */
export default function ClientsPage() {
  const tenant = useConsoleTenant();
  const sp = useSearchParams();
  const router = useRouter();
  const id = sp.get("client");
  const [wizard, setWizard] = useState(sp.get("new") === "1");
  const [revealed, setRevealed] = useState<Revealed | null>(null);
  const [goTo, setGoTo] = useState<string | null>(null);

  if (!tenant) return <Spinner label="Loading…" />;
  if (id) return <ClientDetail key={id} tenant={tenant} id={id} />;

  const onCreated = (created: RevealView) => {
    const target = clientHref(tenant, created.id);
    if (created.client_secret) {
      setGoTo(target);
      setRevealed({
        title: `${created.name} created`,
        description: "Copy the client secret now; it cannot be shown again.",
        values: [
          { label: "Client ID", value: created.client_id },
          { label: "Client secret", value: created.client_secret },
        ],
      });
    } else {
      router.push(target);
    }
  };

  return (
    <>
      <ClientsTable tenant={tenant} onCreate={() => setWizard(true)} />
      <ClientWizard tenant={tenant} open={wizard} onOpenChange={setWizard} onCreated={onCreated} />
      <RevealModal
        revealed={revealed}
        onClose={() => {
          setRevealed(null);
          if (goTo) router.push(goTo);
        }}
      />
    </>
  );
}
