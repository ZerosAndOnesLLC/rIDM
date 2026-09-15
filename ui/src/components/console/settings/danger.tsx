"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { TextInput } from "@/components/console/form";
import { Button, Modal } from "@/components/console/ui";
import { useConsole } from "@/lib/console/session";

/** Deleting a tenant: global owners only, slug typed back to confirm. */
export function DangerZone({ slug }: { slug: string }) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState("");
  const del = useMutation({
    mutationFn: async () => {
      const { error } = await client.DELETE("/admin/tenants/{slug}", { params: { path: { slug } } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["tenants"] });
      router.push("/console/tenants/?tenant=master");
    },
  });
  return (
    <section aria-labelledby="danger-title" className="rounded-[calc(var(--radius)+2px)] border border-danger/40 bg-paper">
      <header className="border-b border-line px-5 py-4">
        <h2 id="danger-title" className="text-[1rem] font-semibold text-danger">
          Delete this tenant
        </h2>
        <p className="mt-1 text-[0.875rem] text-muted">Removes every user, client, key and record of the tenant. There is no undo.</p>
      </header>
      <div className="px-5 py-4">
        <Button variant="danger" onClick={() => setOpen(true)}>
          Delete tenant…
        </Button>
      </div>
      <Modal open={open} onOpenChange={setOpen} title={`Delete ${slug}?`} description="Type the tenant slug to confirm.">
        <div className="flex flex-col gap-4 px-5 pb-5 pt-3">
          <TextInput aria-label="Tenant slug" value={typed} onChange={(e) => setTyped(e.target.value)} placeholder={slug} autoComplete="off" />
          {del.isError && (
            <p role="alert" className="text-[0.875rem] text-danger">
              {del.error.message}
            </p>
          )}
          <div className="flex justify-end gap-2">
            <Button onClick={() => setOpen(false)}>Cancel</Button>
            <Button variant="danger" disabled={typed !== slug || del.isPending} onClick={() => del.mutate()}>
              {del.isPending ? "Deleting…" : "Delete tenant"}
            </Button>
          </div>
        </div>
      </Modal>
    </section>
  );
}
