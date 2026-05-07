#!/usr/bin/env node
// Bootstrap CLI for the first NDMA root user.
//
// Usage:
//   node server/tm/bootstrap.js --email NAME@example.com \
//     --name "Real Name" --password '<min 8 chars>'
//
// Password may be piped on stdin (use --password "-").
//
// Refuses to run if any user already exists, unless TM_BOOTSTRAP_FORCE=1
// is set in the environment. Requires ADC credentials with Firestore
// access (`gcloud auth application-default login`).
//
// Production deploy: run this once, then pass the credentials to the
// operator out of band. The operator signs in at /tm/#/login with
// {email, password}.

import { argv, exit, env, stdin } from 'node:process';
import { hashPassword } from './auth.js';
import { bootstrapWithPassword } from './users.js';

const PASSWORD_MIN_LEN = 8;
const PASSWORD_MAX_LEN = 256;

function parseArgs(args) {
  const out = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--email') out.email = args[++i];
    else if (a === '--name') out.name = args[++i];
    else if (a === '--password') out.password = args[++i];
    else if (a === '--help' || a === '-h') out.help = true;
  }
  return out;
}

function usage() {
  process.stdout.write([
    'Aether TM bootstrap',
    '',
    'Usage:',
    '  node server/tm/bootstrap.js --email <email> --name <name> --password <pw|->',
    '',
    'Reads password from stdin if --password is "-".',
    'Refuses to run if users already exist (override with TM_BOOTSTRAP_FORCE=1).',
    '',
    'Environment:',
    '  GCP_PROJECT          Firestore project id (default dmjone)',
    '  FIRESTORE_DB         database id (default "(default)")',
    '  TM_BOOTSTRAP_FORCE   set to 1 to allow bootstrap when users exist',
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
  if (!opts.email || !opts.name || !opts.password) {
    usage();
    process.stderr.write('error: --email, --name, and --password are required\n');
    exit(2);
  }
  let password = opts.password;
  if (password === '-') password = await readStdin();
  password = String(password);
  if (password.length < PASSWORD_MIN_LEN || password.length > PASSWORD_MAX_LEN) {
    process.stderr.write(`error: password must be ${PASSWORD_MIN_LEN}..${PASSWORD_MAX_LEN} chars\n`);
    exit(2);
  }

  try {
    const cred = hashPassword(password);
    const u = await bootstrapWithPassword(opts.email, opts.name, cred.saltB64u, cred.hashB64u);
    process.stdout.write([
      'Bootstrap complete.',
      `  uid:        ${u.uid}`,
      `  email:      ${u.email}`,
      `  name:       ${u.name}`,
      `  tier:       ${u.tier_name} (${u.tier})`,
      `  scope_path: ${u.scope_path}`,
      '',
      'Sign in at /tm/#/login with this email and the password above.',
      'Lose the password and the account is unrecoverable until you re-bootstrap.',
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
