"use client";

import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { TextArea } from "@/components/console/form";
import { Badge, Button, Modal } from "@/components/console/ui";
import { adminBase, downloadWithToken } from "@/lib/console/ops";
import { sessionStore, useConsole } from "@/lib/console/session";

type Report = { dry_run: boolean; total: number; created: number; failed: number; errors: { row: number; username?: string | null; error: string }[] };

/**
 * Bulk import: paste or pick a JSON array or CSV; a dry run reports every
 * row that would fail before anything is written.
 */
export function ImportUsers({ tenant, open, onOpenChange, onImported }: { tenant: string; open: boolean; onOpenChange: (o: boolean) => void; onImported: () => void }) {
  const [text, setText] = useState("");
  const [format, setFormat] = useState<"json" | "csv">("json");
  const [report, setReport] = useState<Report | null>(null);
  const run = useMutation({
    mutationFn: async (dryRun: boolean): Promise<Report> => {
      const token = await sessionStore.token();
      const res = await fetch(`${adminBase()}/admin/tenants/${encodeURIComponent(tenant)}/users/import?dry_run=${dryRun}`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": format === "csv" ? "text/csv" : "application/json", Accept: "application/json" },
        body: text,
      });
      const body = (await res.json().catch(() => null)) as (Report & { detail?: string; title?: string }) | null;
      if (!res.ok || !body) throw new Error(body?.detail ?? body?.title ?? `Import failed (${res.status}).`);
      return body;
    },
    onSuccess: (r) => {
      setReport(r);
      if (!r.dry_run && r.created > 0) onImported();
    },
  });
  const pick = async (file: File | undefined) => {
    if (!file) return;
    setFormat(file.name.toLowerCase().endsWith(".csv") ? "csv" : "json");
    setText(await file.text());
    setReport(null);
  };
  const close = (o: boolean) => {
    if (!o) {
      setReport(null);
      run.reset();
    }
    onOpenChange(o);
  };
  return (
    <Modal open={open} onOpenChange={close} title="Import users" description="JSON (an array of users) or CSV with a header row; attr.<name> columns become profile attributes." size="lg">
      <div className="flex flex-col gap-4 overflow-y-auto px-5 pb-5 pt-3">
        <div className="flex flex-wrap items-center gap-3">
          <label className="text-[0.875rem] text-ink">
            <span className="sr-only">Choose a file</span>
            <input type="file" accept=".json,.csv,application/json,text/csv" onChange={(e) => void pick(e.target.files?.[0])} className="text-[0.8125rem] text-muted file:me-3 file:rounded-[var(--radius)] file:border file:border-line file:bg-paper file:px-3 file:py-1.5 file:text-[0.8125rem] file:text-ink" />
          </label>
          <label className="flex items-center gap-2 text-[0.875rem] text-ink">
            <input type="radio" name="fmt" checked={format === "json"} onChange={() => setFormat("json")} className="accent-[var(--accent)]" /> JSON
          </label>
          <label className="flex items-center gap-2 text-[0.875rem] text-ink">
            <input type="radio" name="fmt" checked={format === "csv"} onChange={() => setFormat("csv")} className="accent-[var(--accent)]" /> CSV
          </label>
        </div>
        <TextArea
          aria-label="Users to import"
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            setReport(null);
          }}
          placeholder={format === "csv" ? "username,email,password,roles\nalice,alice@example.com,S3cret-pass-word,editor" : '[{"username": "alice", "email": "alice@example.com", "password": "S3cret-pass-word", "roles": ["editor"]}]'}
          className="min-h-40"
        />
        {run.isError && (
          <p role="alert" className="text-[0.875rem] text-danger">
            {run.error.message}
          </p>
        )}
        {report && (
          <div className="rounded-[var(--radius)] border border-line">
            <div className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-2.5 text-[0.875rem]" role="status">
              <Badge tone={report.dry_run ? "accent" : "ok"}>{report.dry_run ? "Dry run" : "Imported"}</Badge>
              <span>
                {report.total} rows · {report.created} {report.dry_run ? "would be created" : "created"} · {report.failed} failed
              </span>
            </div>
            {report.errors.length > 0 && (
              <ul className="max-h-48 overflow-y-auto px-4 py-2 text-[0.8125rem]">
                {report.errors.map((e) => (
                  <li key={`${e.row}-${e.error}`} className="py-1 text-danger">
                    Row {e.row}
                    {e.username ? ` (${e.username})` : ""}: {e.error}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
        <div className="flex justify-end gap-2">
          <Button onClick={() => close(false)}>Done</Button>
          <Button disabled={!text.trim() || run.isPending} onClick={() => run.mutate(true)}>
            Dry run
          </Button>
          <Button variant="primary" disabled={!text.trim() || run.isPending || !report?.dry_run || report.failed === report.total} onClick={() => run.mutate(false)}>
            {run.isPending ? "Working…" : "Import"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

/** Fetch the export with the console's token and hand the file to the browser. */
export function ExportUsers({ tenant, open, onOpenChange }: { tenant: string; open: boolean; onOpenChange: (o: boolean) => void }) {
  const { can } = useConsole();
  const [format, setFormat] = useState<"json" | "csv">("json");
  const download = useMutation({
    mutationFn: async () => {
      await downloadWithToken(`/admin/tenants/${encodeURIComponent(tenant)}/users/export?format=${format}`, `${tenant}-users.${format}`);
    },
    onSuccess: () => onOpenChange(false),
  });
  return (
    <Modal open={open} onOpenChange={onOpenChange} title="Export users" description="Every live user, without credentials.">
      <div className="flex flex-col gap-4 px-5 pb-5 pt-3">
        <fieldset className="flex gap-4">
          <legend className="sr-only">Format</legend>
          <label className="flex items-center gap-2 text-[0.875rem] text-ink">
            <input type="radio" name="export-fmt" checked={format === "json"} onChange={() => setFormat("json")} className="accent-[var(--accent)]" /> JSON
          </label>
          <label className="flex items-center gap-2 text-[0.875rem] text-ink">
            <input type="radio" name="export-fmt" checked={format === "csv"} onChange={() => setFormat("csv")} className="accent-[var(--accent)]" /> CSV
          </label>
        </fieldset>
        {download.isError && (
          <p role="alert" className="text-[0.875rem] text-danger">
            {download.error.message}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <Button onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button variant="primary" disabled={!can("ridm:users:read") || download.isPending} onClick={() => download.mutate()}>
            {download.isPending ? "Preparing…" : "Download"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}
