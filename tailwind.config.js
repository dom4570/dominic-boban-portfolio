/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        obsidian: "#05070d",
        graphite: "#11100b",
        signal: "#fcee0a",
        volt: "#ffb000",
        trace: "#ff2a3d",
        haze: "#d7c99e"
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "SFMono-Regular", "Consolas", "monospace"]
      },
      boxShadow: {
        glow: "0 0 44px rgba(252, 238, 10, 0.22)",
        trace: "0 0 34px rgba(255, 42, 61, 0.2)"
      },
      backgroundImage: {
        "radial-signal": "radial-gradient(circle at 20% 20%, rgba(252,238,10,0.18), transparent 30%), radial-gradient(circle at 80% 10%, rgba(255,42,61,0.14), transparent 28%), radial-gradient(circle at 50% 90%, rgba(255,176,0,0.12), transparent 26%)"
      }
    }
  },
  plugins: []
};
