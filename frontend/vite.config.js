import { defineConfig } from 'vite';
export default defineConfig({base:'/soc/',build:{outDir:'../prototype/soc',emptyOutDir:true,rollupOptions:{output:{entryFileNames:'app.js',assetFileNames:a=>a.names?.some(n=>n.endsWith('.css'))?'app.css':'[name][extname]'}}},server:{proxy:{'/api':'http://127.0.0.1:8765'}}});
