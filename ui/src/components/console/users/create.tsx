"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { Field, SelectInput, TextInput, Toggle } from "@/components/console/form";
import { Button, Modal } from "@/components/console/ui";
import { useConsole } from "@/lib/console/session";
import { userHref } from "@/lib/console/users";
import type { Revealed } from "../clients/reveal";

type PasswordMode = "temporary" | "set" | "none";

/** Create a user; a temporary password is revealed once. */
export function CreateUser({ tenant, open, onOpenChange, onReveal }: { tenant: string; open: boolean; onOpenChange: (o: boolean) => void; onReveal: (r: Revealed, then: string) => void }) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [verified, setVerified] = useState(true);
  const [phone, setPhone] = useState("");
  const [mode, setMode] = useState<PasswordMode>("temporary");
  const [password, setPassword] = useState("");
  const create = useMutation({
    mutationFn: async () => {
      const body: Record<string, unknown> = {
        username: username.trim(),
        email: email.trim() || null,
        email_verified: Boolean(email.trim()) && verified,
        phone: phone.trim() || null,
      };
      if (mode === "temporary") body.temporary_password = true;
      if (mode === "set") body.password = password;
      const { data, error } = await client.POST("/admin/tenants/{slug}/users", { params: { path: { slug: tenant } }, body: body as never });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: (u) => {
      void qc.invalidateQueries({ queryKey: ["users", tenant] });
      onOpenChange(false);
      const target = userHref(tenant, u.id);
      if (u.temporary_password) {
        onReveal(
          {
            title: `${u.username} created`,
            description: "Hand this temporary password to the user; they must change it at first sign-in.",
            values: [{ label: "Temporary password", value: u.temporary_password }],
          },
          target,
        );
      } else {
        router.push(target);
      }
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!username.trim() || (mode === "set" && !password)) return;
    create.mutate();
  };
  return (
    <Modal open={open} onOpenChange={onOpenChange} title="New user" description="Accounts created here are active at once.">
      <form onSubmit={submit} className="flex flex-col gap-4 px-5 pb-5 pt-3" noValidate>
        <Field label="Username">{(id) => <TextInput id={id} value={username} onChange={(e) => setUsername(e.target.value)} autoFocus autoCapitalize="none" spellCheck={false} required />}</Field>
        <Field label="Email">{(id) => <TextInput id={id} type="email" value={email} onChange={(e) => setEmail(e.target.value)} />}</Field>
        {email.trim() && <Toggle label="Email is verified" hint="Off sends nothing; the user verifies through recovery or the account console." checked={verified} onChange={setVerified} />}
        <Field label="Phone">{(id) => <TextInput id={id} type="tel" value={phone} onChange={(e) => setPhone(e.target.value)} />}</Field>
        <Field label="Password">
          {(id) => (
            <SelectInput id={id} value={mode} onChange={(e) => setMode(e.target.value as PasswordMode)}>
              <option value="temporary">Generate a temporary password (shown once)</option>
              <option value="set">Set a password now</option>
              <option value="none">No password (passwordless or invitation later)</option>
            </SelectInput>
          )}
        </Field>
        {mode === "set" && <Field label="New password">{(id) => <TextInput id={id} type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} required />}</Field>}
        {create.isError && (
          <p role="alert" className="text-[0.875rem] text-danger">
            {create.error.message}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <Button onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={create.isPending}>
            {create.isPending ? "Creating…" : "Create user"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
