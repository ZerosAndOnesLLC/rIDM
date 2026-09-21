"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import { ExternalLink, UserRoundCog } from "lucide-react";
import { useState } from "react";
import { Field, TextArea } from "@/components/console/form";
import { Button, Modal } from "@/components/console/ui";
import { useConsole } from "@/lib/console/session";

const REASON_MAX = 500;

/**
 * "Sign in as this user": asks for a reason, then hands over a one-time link
 * that opens a session as the user in a new tab. Shown only where it could
 * work — the caller holds `ridm:users:impersonate`, the tenant allows it, and
 * the user is active. The server refuses administrators as targets.
 */
export function ImpersonateAction({ tenant, userId, username, active }: { tenant: string; userId: string; username: string; active: boolean }) {
  const { client: api, can } = useConsole();
  const allowed = can("ridm:users:impersonate");
  const settings = useQuery({
    queryKey: ["tenant", tenant],
    enabled: allowed,
    queryFn: async () => {
      const { data, error } = await api.GET("/admin/tenants/{slug}", { params: { path: { slug: tenant } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const start = useMutation({
    mutationFn: async () => {
      const { data, error } = await api.POST("/admin/tenants/{slug}/users/{user}/impersonate", {
        params: { path: { slug: tenant, user: userId } },
        body: { reason: reason.trim() },
      });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });

  if (!allowed || !active || !settings.data?.settings.impersonation.enabled) return null;

  const close = (next: boolean) => {
    setOpen(next);
    if (!next) {
      setReason("");
      start.reset();
    }
  };
  const tooLong = reason.length > REASON_MAX;
  const minutes = settings.data.settings.impersonation.max_minutes;

  return (
    <>
      <Button onClick={() => setOpen(true)}>
        <UserRoundCog className="size-4" aria-hidden />
        Impersonate
      </Button>
      <Modal
        open={open}
        onOpenChange={close}
        title={`Sign in as ${username}`}
        description={`A session as ${username} opens in a new tab and lasts up to ${minutes} minutes. Everything done in it is recorded under your name. You can't change the user's credentials or give consent for them.`}
      >
        <div className="flex flex-col gap-4 px-5 pb-5 pt-3">
          {start.data ? (
            <>
              <p className="text-[0.875rem] text-ink">The link works once, within a minute. In this browser it replaces any session you already have in this tenant until you end the impersonation.</p>
              <div className="flex flex-wrap justify-end gap-2">
                <Button onClick={() => close(false)}>Close</Button>
                <a
                  href={start.data.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={() => close(false)}
                  className="inline-flex min-h-9 items-center justify-center gap-2 rounded-[var(--radius)] bg-accent px-3.5 text-[0.875rem] font-medium text-accent-ink hover:brightness-110"
                >
                  <ExternalLink className="size-4" aria-hidden />
                  Open session as {username}
                </a>
              </div>
            </>
          ) : (
            <form
              className="flex flex-col gap-4"
              onSubmit={(e) => {
                e.preventDefault();
                if (reason.trim() && !tooLong) start.mutate();
              }}
            >
              <Field label="Reason" hint="Recorded in the audit log with the impersonation, e.g. a support ticket number." error={tooLong ? `Keep it under ${REASON_MAX} characters.` : null}>
                {(id, by) => <TextArea id={id} aria-describedby={by} value={reason} onChange={(e) => setReason(e.target.value)} required className="font-sans text-[0.875rem]" />}
              </Field>
              {start.isError && (
                <p role="alert" className="text-[0.875rem] text-danger">
                  {start.error.message}
                </p>
              )}
              <div className="flex justify-end gap-2">
                <Button onClick={() => close(false)}>Cancel</Button>
                <Button type="submit" variant="primary" disabled={!reason.trim() || tooLong || start.isPending}>
                  Continue
                </Button>
              </div>
            </form>
          )}
        </div>
      </Modal>
    </>
  );
}
