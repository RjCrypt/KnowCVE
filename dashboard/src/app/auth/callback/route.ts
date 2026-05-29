import { createServerClient, type CookieOptions } from "@supabase/ssr";
import { cookies } from "next/headers";
import { NextResponse } from "next/server";

export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url);
  const code = searchParams.get("code");
  const invite = searchParams.get("invite");
  const appUrl = process.env.NEXT_PUBLIC_APP_URL || origin;
  const apiBase = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

  if (!code) {
    return NextResponse.redirect(`${appUrl}/auth/login?error=true`);
  }

  try {
    const cookieStore = cookies();

    const supabase = createServerClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
      {
        cookies: {
          get(name: string) {
            return cookieStore.get(name)?.value;
          },
          set(name: string, value: string, options: CookieOptions) {
            cookieStore.set({ name, value, ...options });
          },
          remove(name: string, options: CookieOptions) {
            cookieStore.set({ name, value: "", ...options });
          },
        },
      }
    );

    // Exchange code for session
    const { data, error } = await supabase.auth.exchangeCodeForSession(code);

    if (error || !data.user) {
      console.error("Auth callback error:", error);
      return NextResponse.redirect(`${appUrl}/auth/login?error=true`);
    }

    const user = data.user;

    // POST to backend to upsert profile
    let isNewUser = false;
    try {
      const profileRes = await fetch(`${apiBase}/api/auth/profile`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id: user.id,
          email: user.email || "",
          display_name:
            user.user_metadata?.full_name ||
            user.user_metadata?.name ||
            user.email?.split("@")[0] ||
            null,
          avatar_url:
            user.user_metadata?.avatar_url ||
            user.user_metadata?.picture ||
            null,
        }),
      });

      if (profileRes.ok) {
        const profileData = await profileRes.json();
        isNewUser = !!profileData.is_new_user;
      }
    } catch (err) {
      // Non-fatal — user is authenticated even if profile sync fails
      console.error("Profile sync failed:", err);
    }

    // If invite token is present, try to auto-accept
    if (invite) {
      try {
        const acceptRes = await fetch(
          `${apiBase}/api/invites/accept/${invite}?user_id=${user.id}`
        );
        if (acceptRes.ok) {
          const acceptData = await acceptRes.json();
          if (acceptData.org_id && !acceptData.requires_signup) {
            return NextResponse.redirect(
              `${appUrl}/org/${acceptData.org_id}/dashboard`
            );
          }
        }
      } catch (err) {
        console.error("Invite auto-accept failed:", err);
      }
      // If auto-accept failed, redirect to the invite page so user can try manually
      return NextResponse.redirect(`${appUrl}/invites/accept/${invite}`);
    }

    // No invite — normal flow
    if (isNewUser) {
      return NextResponse.redirect(`${appUrl}/onboarding`);
    }

    // Existing user → redirect home
    return NextResponse.redirect(`${appUrl}/`);
  } catch (err) {
    console.error("Auth callback unexpected error:", err);
    return NextResponse.redirect(`${appUrl}/auth/login?error=true`);
  }
}
