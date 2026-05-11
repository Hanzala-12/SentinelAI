/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: '#07111f',
        surface: '#0f1b2e',
        accent: '#36d399',
        warning: '#fbbf24',
        danger: '#f87171',
        text: '#e5eefc',
        muted: '#91a4c7',
      },
      boxShadow: {
        glow: '0 0 0 1px rgba(54, 211, 153, 0.18), 0 16px 48px rgba(5, 10, 20, 0.45)',
      },
      backgroundImage: {
        'hero-grid':
          'radial-gradient(circle at top left, rgba(54,211,153,0.12), transparent 28%), radial-gradient(circle at top right, rgba(56,189,248,0.10), transparent 20%), linear-gradient(180deg, #07111f 0%, #0c1627 100%)',
      },
    },
  },
  plugins: [],
}
