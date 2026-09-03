import { copyFile, mkdir } from 'node:fs/promises';
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

await copyFile(
  new URL('../node_modules/altcha/dist/external/altcha.css', import.meta.url),
  new URL('../public/assets/altcha-v3-2-2.css', import.meta.url),
);

console.log('self-hosted browser assets built');
