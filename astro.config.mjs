import { defineConfig } from 'astro/config';
import vercel from '@astrojs/vercel';
import tailwind from '@astrojs/tailwind';

export default defineConfig({
  integrations: [tailwind()],
  output: "hybrid",
  vite: {
    ssr: {
      noExternal: ['flatpickr'] 
    }
  }
});