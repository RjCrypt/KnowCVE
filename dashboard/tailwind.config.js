/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        void:      "#080a0f",
        surface:   "#0d1117",
        panel:     "#161b22",
        border:    "#21262d",
        muted:     "#30363d",
        acid:      "#00ff88",
        "acid-dim":"#00cc6a",
        amber:     "#f0a500",
        danger:    "#ff4444",
        info:      "#4d9de0",
        "l-bg":      "#f4f5f7",
        "l-surface": "#ffffff",
        "l-panel":   "#f0f1f3",
        "l-border":  "#e1e4e8",
        "l-muted":   "#d0d7de",
        "l-text":    "#1c2128",
        "l-sub":     "#57606a",
      },
      fontFamily: {
        display: ["var(--font-display)", "sans-serif"],
        sans:    ["var(--font-sans)", "sans-serif"],
        mono:    ["var(--font-mono)", "monospace"],
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4,0,0.6,1) infinite",
        "fade-in":    "fadeIn 0.4s ease forwards",
        "slide-up":   "slideUp 0.35s ease forwards",
        marquee: "marquee 50s linear infinite",
      },
      keyframes: {
        fadeIn:  { from: { opacity: "0" }, to: { opacity: "1" } },
        slideUp: { from: { opacity: "0", transform: "translateY(12px)" }, to: { opacity: "1", transform: "translateY(0)" } },
        marquee: { "0%": { transform: "translateX(0%)" }, "100%": { transform: "translateX(-100%)" } },
      },
    },
  },
  plugins: [],
};
