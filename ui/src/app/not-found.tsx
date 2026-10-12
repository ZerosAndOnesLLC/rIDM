import { ErrorFallback } from "@/components/base/error-fallback";

/** `404.html` in the static export; the embedded UI and file hosts serve it for unknown paths. */
export default function NotFound() {
  return (
    <main className="min-h-screen">
      <ErrorFallback kind="not-found" />
    </main>
  );
}
