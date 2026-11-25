/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#1a2332',
          surface: '#111824',
          panel: '#202b3d',
          border: '#2d3b52',
          text: '#a4b1cd',
          heading: '#e2e8f0',
          safe: '#2ee7b6',
          alert: '#f43f5e',
          warn: '#f59e0b',
          info: '#38bdf8',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"Fira Code"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
    },
  },
  plugins: [],
}
