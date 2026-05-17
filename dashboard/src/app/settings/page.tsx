"use client";

import { Settings, Construction } from "lucide-react";
import Footer from "@/components/layout/Footer";

export default function SettingsPage() {
  return (
    <div className="mx-auto max-w-4xl px-4 sm:px-6 py-8 animate-fade-in">
      <div className="flex items-center gap-3 mb-8">
        <div className="p-2 rounded-xl bg-l-panel dark:bg-panel border border-l-border dark:border-border">
          <Settings className="h-6 w-6 text-l-sub dark:text-gray-400" />
        </div>
        <div>
          <h1 className="text-2xl font-display font-bold text-l-text dark:text-gray-100">
            Settings
          </h1>
          <p className="text-sm text-l-sub dark:text-gray-400">
            Manage your account preferences
          </p>
        </div>
      </div>

      <div className="card p-12 text-center">
        <Construction className="h-12 w-12 mx-auto text-l-muted dark:text-muted mb-4" />
        <h2 className="font-display font-bold text-lg text-l-text dark:text-gray-200 mb-2">
          Settings — Coming Soon
        </h2>
        <p className="text-sm text-l-sub dark:text-gray-500 max-w-sm mx-auto">
          Profile management, notification preferences, API keys, and more will
          be available here in a future update.
        </p>
      </div>

      <div className="mt-12" />
      <Footer />
    </div>
  );
}
