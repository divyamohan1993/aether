// Build the browser auth client bundle.
//
// Reads server/tm/_browser/auth-client.src.js, resolves npm imports
// from server/node_modules, and writes web/tm/auth-client.js. Also
// emits .gz and .br pre-compressed companions so the static server
// can serve them with Content-Encoding without paying the CPU cost
// at request time.

import { promises as fs } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { gzipSync, brotliCompressSync, constants as zlibConst } from 'node:zlib';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const esbuildEntry = pathToFileURL(join(ROOT, 'server', 'node_modules', 'esbuild', 'lib', 'main.js')).href;
const { build } = await import(esbuildEntry);
const ENTRY = join(ROOT, 'server', 'tm', '_browser', 'auth-client.src.js');
const OUT = join(ROOT, 'web', 'tm', 'auth-client.js');

await build({
  entryPoints: [ENTRY],
  bundle: true,
  format: 'esm',
  target: ['es2022'],
  outfile: OUT,
  minify: true,
  legalComments: 'none',
  nodePaths: [join(ROOT, 'server', 'node_modules')]
});

const buf = await fs.readFile(OUT);
const gz = gzipSync(buf, { level: 9 });
const br = brotliCompressSync(buf, {
  params: {
    [zlibConst.BROTLI_PARAM_QUALITY]: 11,
    [zlibConst.BROTLI_PARAM_SIZE_HINT]: buf.length
  }
});
await fs.writeFile(OUT + '.gz', gz);
await fs.writeFile(OUT + '.br', br);

process.stdout.write(`build-auth-client: ${buf.length} bytes (gz ${gz.length}, br ${br.length})\n`);
