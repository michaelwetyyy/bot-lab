import { mkdir } from 'node:fs/promises';
import { build } from 'esbuild';

await mkdir(new URL('../public/assets/', import.meta.url), { recursive: true });

await build({
  entryPoints: [new URL('../src/client.js', import.meta.url).pathname],
  outfile: new URL('../public/assets/app-v6-2.js', import.meta.url).pathname,
  bundle: true,
  format: 'esm',
  minify: true,
  sourcemap: false,
  target: ['es2022'],
  legalComments: 'eof',
});

console.log('public/assets/app-v6-2.js built');
