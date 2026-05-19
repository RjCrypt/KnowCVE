import { createServerClient, type CookieOptions } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";

export async function middleware(request: NextRequest) {
  let response = NextResponse.next({
    request: { headers: request.headers },
  });

  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  if (!supabaseUrl || !supabaseAnonKey) {
    // Missing env vars (e.g. on Vercel preview or first deploy), pass through without auth checks to avoid 500 errors
    return response;
  }

  const supabase = createServerClient(
    supabaseUrl,
    supabaseAnonKey,
    {
      cookies: {
        getAll() {
          return request.cookies.getAll();
        },
        setAll(cookiesToSet) {
          cookiesToSet.forEach(({ name, value, options }) => {
            request.cookies.set(name, value);
          });
          response = NextResponse.next({
            request,
          });
          cookiesToSet.forEach(({ name, value, options }) => {
            response.cookies.set(name, value, options);
          });
        },
      },
    }
  );

  try {
    // Refresh the session on every request
    const {
      data: { user },
    } = await supabase.auth.getUser();

    // Protected routes — redirect to login if no user
    const protectedPaths = ["/workspace", "/bookmarks", "/onboarding", "/settings"];
    const isProtected = protectedPaths.some((path) =>
      request.nextUrl.pathname.startsWith(path)
    );

    if (isProtected && !user) {
      const loginUrl = new URL("/auth/login", request.url);
      return NextResponse.redirect(loginUrl);
    }

    // If user is on login page but already authenticated, redirect to home
    if (request.nextUrl.pathname === "/auth/login" && user) {
      const homeUrl = new URL("/", request.url);
      return NextResponse.redirect(homeUrl);
    }
  } catch (e) {
    // Fail gracefully if Supabase is unreachable
    console.error("Middleware Supabase error:", e);
  }

  return response;
}

export const config = {
  matcher: [
    /*
     * Match all request paths except:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public files (images, etc.)
     */
    "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)",
  ],
};
