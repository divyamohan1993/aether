#!/usr/bin/env node
// Bootstrap CLI for the first NDMA root user.
//
// Usage:
//   node server/tm/bootstrap.js --email NAME@example.com \
//     --name "Real Name" --pubkey-b64 <base64>
//
// Pubkey may also be piped on stdin (the --pubkey-b64 flag is then "-").
//
// Refuses to run if any user already exists, unless TM_BOOTSTRAP_FORCE=1
// is set in the environment. Requires ADC credentials with Firestore
// access (`gcloud auth application-default login`).

import { argv, exit, env, stdin } from 'node:process';
import { bootstrap } from './users.js';

function parseArgs(args) {
  const out = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--email') out.email = args[++i];
    else if (a === '--name') out.name = args[++i];
    else if (a === '--pubkey-b64') out.pubkey = args[++i];
    else if (a === '--help' || a === '-h') out.help = true;
  }
  return out;
}

function usage() {
  process.stdout.write([
    'Aether TM bootstrap',
    '',
    'Usage:',
    '  node server/tm/bootstrap.js --email <email> --name <name> --pubkey-b64 <b64|->',
    '',
    'Reads pubkey from stdin if --pubkey-b64 is "-".',
    'Refuses to run if users already exist (override with TM_BOOTSTRAP_FORCE=1).',
    '',
    'Environment:',
    '  GCP_PROJECT       Firestore project id (default dmjone)',
    '  FIRESTORE_DB      database id (default "(default)")',
    '  TM_BOOTSTRAP_FORCE  set to 1 to allow bootstrap when users exist',
    ''
  ].join('\n'));
}

async function readStdin() {
  const chunks = [];
  for await (const c of stdin) chunks.push(c);
  return Buffer.concat(chunks).toString('utf8').trim();
}

async function main() {
  const opts = parseArgs(argv.slice(2));
  if (opts.help) { usage(); return; }
  if (!opts.email || !opts.name || !opts.pubkey) {
    usage();
    process.stderr.write('error: --email, --name, and --pubkey-b64 are required\n');
    exit(2);
  }
  let pubkey = opts.pubkey;
  if (pubkey === '-') pubkey = await readStdin();
  pubkey = String(pubkey).replace(/\s+/g, '');

  try {
    const u = await bootstrap(opts.email, opts.name, pubkey);
    process.stdout.write([
      'Bootstrap complete.',
      `  uid:        ${u.uid}`,
      `  email:      ${u.email}`,
      `  name:       ${u.name}`,
      `  tier:       ${u.tier_name} (${u.tier})`,
      `  scope_path: ${u.scope_path}`,
      '',
      'Save the uid and the user\'s private key. The server only stores',
      `the public key. Login at /tm/login with this email and the`,
      `passphrase used to encrypt the private key on the client.`,
      ''
    ].join('\n'));
  } catch (e) {
    const code = e?.code || 'unknown';
    const msg = e?.message || String(e);
    process.stderr.write(`Bootstrap failed [${code}]: ${msg}\n`);
    if (env.DEBUG) process.stderr.write(`${e?.stack || ''}\n`);
    exit(1);
  }
}

main();
