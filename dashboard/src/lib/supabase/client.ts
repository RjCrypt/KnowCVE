import { createBrowserClient } from "@supabase/ssr";

export function createClient() {
  let rawUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || "";
  rawUrl = rawUrl.trim();
  if (rawUrl && !rawUrl.startsWith("http")) {
    rawUrl = `https://${rawUrl}`;
  }

  return createBrowserClient(
    rawUrl,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || ""
  );
}
