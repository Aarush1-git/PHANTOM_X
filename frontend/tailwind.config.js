/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        phantom: {
          950: "#07090e",
          900: "#0b0f17",
          850: "#101622",
          800: "#161f30",
          700: "#1e2b42",
          600: "#2d3e5e",
        },
        cyber: {
          emerald: "#10b981",
          cyan: "#06b6d4",
          amber: "#f59e0b",
          rose: "#f43f5e",
          violet: "#8b5cf6",
        }
      },
      fontFamily: {
        mono: ["JetBrains Mono", "Menlo", "Monaco", "Consolas", "Courier New", "monospace"],
      }
    },
  },
  plugins: [],
}

