import { createClient } from "@/lib/supabase/server";
import { NextResponse } from "next/server";

export async function POST(request: Request) {
  const supabase = createClient();
  
  // Clear the session from Supabase
  await supabase.auth.signOut();

  // Create a response that redirects to the homepage
  return NextResponse.redirect(new URL("/", request.url), {
    status: 302,
  });
}
