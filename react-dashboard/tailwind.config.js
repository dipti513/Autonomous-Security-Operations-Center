/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        ink: {
          950: "#07111b",
          900: "#0c1724",
          800: "#132232"
        },
        signal: {
          cyan: "#5ef2ff",
          green: "#9bff9a",
          amber: "#ffd166",
          red: "#ff7b72"
        }
      },
      fontFamily: {
        display: ["Space Grotesk", "sans-serif"],
        mono: ["IBM Plex Mono", "monospace"]
      },
      boxShadow: {
        glow: "0 0 40px rgba(94, 242, 255, 0.12)"
      },
      keyframes: {
        pulseLine: {
          "0%, 100%": { opacity: "0.35" },
          "50%": { opacity: "1" }
        },
        rise: {
          "0%": { opacity: "0", transform: "translateY(12px)" },
          "100%": { opacity: "1", transform: "translateY(0)" }
        }
      },
      animation: {
        pulseLine: "pulseLine 1.4s ease-in-out infinite",
        rise: "rise 400ms ease-out both"
      }
    }
  },
  plugins: []
};

