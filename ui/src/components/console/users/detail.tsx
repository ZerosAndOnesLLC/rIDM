"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Trash2, Unlock } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useState } from "react";
import { Skeleton } from "@/components/base/skeleton";
import { DetailPanel, PanelTabs, panelTabClass } from "@/components/console/panel";
import { Avatar, Badge, Button, IconButton, Modal, Status } from "@/components/console/ui";
import { fmtDate, fmtWhen } from "@/lib/console/format";
import { useConsole } from "@/lib/console/session";
import { STATUS_LABELS, TABS, TAB_LABELS, displayName, statusTone, userHref, type Tab, type UserUpdate } from "@/lib/console/users";
import { RevealModal, type Revealed } from "../clients/reveal";
import { ImpersonateAction } from "./impersonate";
import { GroupsTab, RolesTab } from "./access-tabs";
import { AuditTab, ConsentsTab } from "./activity-tabs";
import { ProfileTab } from "./profile-tab";
import { SecurityTab } from "./security-tab";
import { SessionsTab } from "./sessions-tab";

export function UserDetail({ tenant, id, tab }: { tenant: string; id: string; tab: Tab }) {
  const { client: api, can } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  const editable = can("ridm:users:write");
  const [revealed, setRevealed] = useState<Revealed | null>(null);
  const query = useQuery({
    queryKey: ["user", tenant, id],
    queryFn: async () => {
      const { data, error } = await api.GET("/admin/tenants/{slug}/users/{user}", { params: { path: { slug: tenant, user: id } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const reload = useCallback(() => qc.invalidateQueries({ queryKey: ["user", tenant, id] }), [qc, tenant, id]);
  const act = useMutation({
    mutationFn: async (what: "disable" | "enable" | "unlock" | "force" | "delete") => {
      const path = { slug: tenant, user: id };
      const r =
        what === "unlock"
          ? await api.POST("/admin/tenants/{slug}/users/{user}/unlock", { params: { path } })
          : what === "force"
            ? await api.POST("/admin/tenants/{slug}/users/{user}/force-password-change", { params: { path } })
            : what === "delete"
              ? await api.DELETE("/admin/tenants/{slug}/users/{user}", { params: { path } })
              : await api.PATCH("/admin/tenants/{slug}/users/{user}", { params: { path }, body: { status: what === "disable" ? "disabled" : "active" } as UserUpdate });
      if (r.error) throw new Error(r.error.detail ?? r.error.title);
      return what;
    },
    onSuccess: (what) => {
      void qc.invalidateQueries({ queryKey: ["users", tenant] });
      if (what === "delete") router.push(`/console/users/?tenant=${encodeURIComponent(tenant)}`);
      else void reload();
    },
  });
  const [confirmDelete, setConfirmDelete] = useState(false);

  const listHref = `/console/users/?tenant=${encodeURIComponent(tenant)}`;
  const close = () => router.push(listHref);

  if (query.isError) {
    return (
      <DetailPanel open onClose={close} title="User">
        <p role="alert" className="text-lead text-danger">
          {query.error.message}
        </p>
      </DetailPanel>
    );
  }
  if (!query.data) {
    return (
      <DetailPanel open onClose={close} title="User">
        <Skeleton shape="lines" count={6} label="Loading user…" />
      </DetailPanel>
    );
  }
  const u = query.data;
  const locked = u.status === "locked" || (u.locked_until !== null && u.locked_until !== undefined && new Date(u.locked_until) > new Date());
  const name = displayName(u);

  return (
    <>
      <DetailPanel
        open
        onClose={close}
        backLabel="Back to users"
        mark={<Avatar name={u.username} size="lg" className="shadow-[0_0_0_3px_var(--paper),0_0_0_4px_var(--accent-border)]" />}
        title={
          <>
            <span className="min-w-0 truncate">{name ?? u.username}</span>
            <Status tone={statusTone(u.status)}>{STATUS_LABELS[u.status]}</Status>
            {locked && <Badge tone="warn">Locked</Badge>}
            {u.must_change_password && <Badge>Must change password</Badge>}
          </>
        }
        sub={
          <>
            {name && <span className="font-mono">{u.username}</span>}
            {u.email && <span>{u.email}</span>}
            <span>member since {fmtDate(u.created_at)}</span>
          </>
        }
        actions={
          <>
            <ImpersonateAction tenant={tenant} userId={u.id} username={u.username} active={u.status === "active"} />
            {editable && (
              <>
                {locked && (
                  <Button size="sm" disabled={act.isPending} onClick={() => act.mutate("unlock")}>
                    <Unlock className="size-3.5" aria-hidden />
                    Unlock
                  </Button>
                )}
                <Button size="sm" disabled={act.isPending} onClick={() => act.mutate(u.status === "disabled" ? "enable" : "disable")}>
                  {u.status === "disabled" ? "Enable" : "Disable"}
                </Button>
                <IconButton label="Delete user" onClick={() => setConfirmDelete(true)} className="text-danger hover:bg-danger-soft">
                  <Trash2 className="size-4" aria-hidden />
                </IconButton>
              </>
            )}
          </>
        }
        stats={[
          { label: "Last sign-in", value: u.last_login_at ? fmtWhen(u.last_login_at) : "Never" },
          { label: "Email", value: u.email ? (u.email_verified ? <Badge tone="ok">Verified</Badge> : <Badge tone="warn">Unverified</Badge>) : "—" },
          { label: "Password", value: u.must_change_password ? <Badge tone="warn">Change required</Badge> : u.password_changed_at ? `Changed ${fmtWhen(u.password_changed_at)}` : "Not set" },
          { label: "Member since", value: fmtDate(u.created_at) },
        ]}
        tabs={
          <PanelTabs label="User sections">
            {TABS.map((t) => (
              <Link key={t} href={userHref(tenant, id, t)} aria-current={t === tab ? "page" : undefined} className={panelTabClass(t === tab)}>
                {TAB_LABELS[t]}
              </Link>
            ))}
          </PanelTabs>
        }
      >
        {act.isError && (
          <p role="alert" className="mb-3 text-body text-danger">
            {act.error.message}
          </p>
        )}
        {tab === "profile" && <ProfileTab tenant={tenant} u={u} editable={editable} />}
        {tab === "security" && <SecurityTab tenant={tenant} u={u} editable={editable} onReveal={setRevealed} onChanged={reload} onForce={() => act.mutate("force")} />}
        {tab === "sessions" && <SessionsTab tenant={tenant} id={id} editable={editable} />}
        {tab === "roles" && <RolesTab tenant={tenant} id={id} editable={editable} />}
        {tab === "groups" && <GroupsTab tenant={tenant} id={id} editable={editable} />}
        {tab === "consents" && <ConsentsTab tenant={tenant} id={id} editable={editable} />}
        {tab === "audit" && <AuditTab tenant={tenant} id={id} />}
      </DetailPanel>
      <RevealModal revealed={revealed} onClose={() => setRevealed(null)} />
      <Modal open={confirmDelete} onOpenChange={setConfirmDelete} title={`Delete ${u.username}?`} description="The account is soft-deleted: sessions and devices end at once; it can be purged later.">
        <div className="flex justify-end gap-2 px-5 pb-5 pt-3">
          <Button onClick={() => setConfirmDelete(false)}>Cancel</Button>
          <Button variant="danger" disabled={act.isPending} onClick={() => act.mutate("delete")}>
            Delete user
          </Button>
        </div>
      </Modal>
    </>
  );
}
