"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";
import { RevealModal, type Revealed } from "@/components/console/clients/reveal";
import { CreateUser } from "@/components/console/users/create";
import { UserDetail } from "@/components/console/users/detail";
import { ExportUsers, ImportUsers } from "@/components/console/users/import";
import { InvitationsList, InviteUser } from "@/components/console/users/invite";
import { UsersTable } from "@/components/console/users/table";
import { Button, PageHeader } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { useQueryClient } from "@tanstack/react-query";
import { useConsoleTenant } from "@/lib/console/tenant";
import { TABS, type Tab } from "@/lib/console/users";
import Link from "next/link";

/** `/console/users/`: the table, `?view=invitations`, or one user when `?user=` is set. */
export default function UsersPage() {
  const tenant = useConsoleTenant();
  const sp = useSearchParams();
  const router = useRouter();
  const qc = useQueryClient();
  const id = sp.get("user");
  const tabParam = sp.get("tab");
  const tab: Tab = (TABS as readonly string[]).includes(tabParam ?? "") ? (tabParam as Tab) : "profile";
  const view = sp.get("view");
  const [dialog, setDialog] = useState<"create" | "invite" | "import" | "export" | null>(null);
  const [revealed, setRevealed] = useState<Revealed | null>(null);
  const [goTo, setGoTo] = useState<string | null>(null);

  if (!tenant) return <Spinner label="Loading…" />;
  if (id) return <UserDetail tenant={tenant} id={id} tab={tab} />;
  if (view === "invitations") {
    return (
      <>
        <PageHeader
          title="Invitations"
          sub="Open invitations to this tenant."
          actions={
            <>
              <Link href={`/console/users/?tenant=${encodeURIComponent(tenant)}`} className="inline-flex min-h-9 items-center rounded-[var(--radius)] border border-line bg-paper px-3.5 text-[0.875rem] font-medium text-ink hover:bg-ground">
                Users
              </Link>
              <Button variant="primary" onClick={() => setDialog("invite")}>
                Invite
              </Button>
            </>
          }
        />
        <InvitationsList tenant={tenant} />
        <InviteUser tenant={tenant} open={dialog === "invite"} onOpenChange={(o) => setDialog(o ? "invite" : null)} />
      </>
    );
  }
  return (
    <>
      <UsersTable tenant={tenant} onCreate={() => setDialog("create")} onInvite={() => setDialog("invite")} onImport={() => setDialog("import")} onExport={() => setDialog("export")} />
      <p className="mt-3 text-[0.8125rem] text-muted">
        <Link href={`/console/users/?tenant=${encodeURIComponent(tenant)}&view=invitations`} className="text-link underline underline-offset-4">
          Open invitations
        </Link>
      </p>
      <CreateUser
        tenant={tenant}
        open={dialog === "create"}
        onOpenChange={(o) => setDialog(o ? "create" : null)}
        onReveal={(r, then) => {
          setGoTo(then);
          setRevealed(r);
        }}
      />
      <InviteUser tenant={tenant} open={dialog === "invite"} onOpenChange={(o) => setDialog(o ? "invite" : null)} />
      <ImportUsers tenant={tenant} open={dialog === "import"} onOpenChange={(o) => setDialog(o ? "import" : null)} onImported={() => void qc.invalidateQueries({ queryKey: ["users", tenant] })} />
      <ExportUsers tenant={tenant} open={dialog === "export"} onOpenChange={(o) => setDialog(o ? "export" : null)} />
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
