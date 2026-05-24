#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

const WARNING_BANNER =
  '!!!!!!!!!!!!!!!!!!!! DO NOT SHARE ANY PART OF THE INFORMATION YOU SEE HERE. THIS INFORMATION IS SENSITIVE AND CAN GRANT ACCESS TO YOUR ACCOUNT. SHARING THIS INFORMATION IS LIKE SHARING YOUR PASSWORD. !!!!!!!!!!!!!!!!!!!!';

function usage() {
  return [
    'Usage:',
    '  node convert-account-json.mjs --input <file> --output <file> --to <codex|sub2api>',
    '',
    'Notes:',
    '  - The script auto-detects the source format.',
    '  - Fields that do not exist in the source format are filled with stable defaults.',
  ].join('\n');
}

function parseArgs(argv) {
  const args = { input: '', output: '', to: '' };
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = argv[i + 1];
    if (arg === '--input' && next) {
      args.input = next;
      i += 1;
      continue;
    }
    if (arg === '--output' && next) {
      args.output = next;
      i += 1;
      continue;
    }
    if (arg === '--to' && next) {
      args.to = next;
      i += 1;
      continue;
    }
    if (arg === '--help' || arg === '-h') {
      args.help = true;
    }
  }
  return args;
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function detectFormat(obj) {
  if (isPlainObject(obj) && 'account_id' in obj && 'access_token' in obj) {
    return 'codex';
  }
  if (isPlainObject(obj) && Array.isArray(obj.accounts) && Array.isArray(obj.proxies)) {
    return 'sub2api';
  }
  if (isPlainObject(obj) && 'account' in obj && 'accessToken' in obj) {
    return 'sub2api';
  }
  throw new Error('Unsupported JSON shape: cannot detect source format.');
}

function base64UrlEncode(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64UrlDecode(input) {
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = normalized.length % 4;
  const padded = normalized + (pad ? '='.repeat(4 - pad) : '');
  return Buffer.from(padded, 'base64').toString('utf8');
}

function decodeJwtPayload(token) {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length < 2) return null;
  try {
    return JSON.parse(base64UrlDecode(parts[1]));
  } catch {
    return null;
  }
}

function nowIso() {
  return new Date().toISOString();
}

function isoFromSeconds(seconds) {
  if (!Number.isFinite(seconds)) return nowIso();
  return new Date(seconds * 1000).toISOString();
}

function secondsFromIso(value) {
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : Math.floor(Date.now() / 1000);
}

function buildDefaultAccount(id, planType) {
  return {
    computeResidency: 'no_constraint',
    id,
    isConversationClassifierEnabledForWorkspace: true,
    isDelinquent: false,
    isFedrampCompliantWorkspace: false,
    isFinservEnabledWorkspace: false,
    planType,
    residencyRegion: 'no_constraint',
    structure: 'personal',
  };
}

function buildDefaultUser(email, decodedToken) {
  const auth = decodedToken?.['https://api.openai.com/auth'] ?? {};
  return {
    acr: 'http://schemas.openid.net/pape/policies/2007/06/multi-factor',
    amr: ['otp', 'mfa', 'urn:openai:amr:otp_totp'],
    email,
    iat: decodedToken?.iat ?? Math.floor(Date.now() / 1000),
    id: auth.user_id ?? auth.chatgpt_user_id ?? 'user-unknown',
    idp: 'google-oauth2',
    mfa: true,
    name: email.split('@')[0] || 'Unknown',
  };
}

function buildSyntheticIdToken(source) {
  const accountId = source.account_id ?? source.account?.id ?? '';
  const planType = source.plan_type ?? source.account?.planType ?? 'plus';
  const email = source.email ?? source.user?.email ?? '';
  const userId = source.user?.id ?? source.user_id ?? 'user-unknown';
  const now = Math.floor(Date.now() / 1000);
  const expires = source.expired ? secondsFromIso(source.expired) : now + 60 * 60 * 24 * 90;
  const payload = {
    iat: now,
    exp: expires,
    'https://api.openai.com/auth': {
      chatgpt_account_id: accountId,
      chatgpt_plan_type: planType,
      chatgpt_user_id: userId,
      user_id: userId,
    },
    email,
  };

  return [
    base64UrlEncode(JSON.stringify({ alg: 'none', typ: 'JWT', cpa_synthetic: true })),
    base64UrlEncode(JSON.stringify(payload)),
    '',
  ].join('.');
}

function getFirstSub2ApiAccount(source) {
  if (!Array.isArray(source.accounts)) return null;
  if (!source.accounts.length) {
    throw new Error('Sub2API import package has no accounts.');
  }
  return source.accounts[0];
}

function sub2ApiAccountToCodexShape(account) {
  const credentials = account?.credentials ?? {};
  return {
    type: 'codex',
    email: credentials.email ?? account?.name ?? '',
    account_id: credentials.chatgpt_account_id ?? '',
    chatgpt_account_id: credentials.chatgpt_account_id ?? '',
    plan_type: credentials.chatgpt_plan_type ?? 'plus',
    chatgpt_plan_type: credentials.chatgpt_plan_type ?? 'plus',
    id_token: credentials.id_token ?? '',
    access_token: credentials.access_token ?? '',
    refresh_token: credentials.refresh_token ?? '',
    session_token: credentials.session_token ?? '',
    expired: credentials.expires_at ?? nowIso(),
    disabled: account?.disabled ?? false,
    id_token_synthetic: false,
  };
}

function toCodex(source) {
  const packageAccount = getFirstSub2ApiAccount(source);
  if (packageAccount) {
    return toCodex(sub2ApiAccountToCodexShape(packageAccount));
  }

  const decodedToken = decodeJwtPayload(source.id_token);
  const email = source.email ?? source.user?.email ?? decodedToken?.email ?? '';
  const accountId = source.account_id ?? source.account?.id ?? decodedToken?.['https://api.openai.com/auth']?.chatgpt_account_id ?? '';
  const planType = source.plan_type ?? source.account?.planType ?? decodedToken?.['https://api.openai.com/auth']?.chatgpt_plan_type ?? 'plus';
  const accessToken = source.access_token ?? source.accessToken ?? '';
  const sessionToken = source.session_token ?? source.sessionToken ?? '';
  const expired = source.expired ?? source.expires ?? nowIso();
  const lastRefresh = source.last_refresh ?? source.expires ?? nowIso();
  const idToken = source.id_token ?? buildSyntheticIdToken({
    account_id: accountId,
    plan_type: planType,
    email,
    user: source.user,
    expired,
  });

  return {
    type: source.type ?? 'codex',
    email,
    account_id: accountId,
    chatgpt_account_id: source.chatgpt_account_id ?? accountId,
    plan_type: planType,
    chatgpt_plan_type: source.chatgpt_plan_type ?? planType,
    id_token: idToken,
    access_token: accessToken,
    refresh_token: source.refresh_token ?? '',
    session_token: sessionToken,
    last_refresh: lastRefresh,
    expired,
    disabled: source.disabled ?? false,
    id_token_synthetic: source.id_token_synthetic ?? !source.id_token,
  };
}

function toSub2Api(source) {
  if (Array.isArray(source.accounts) && Array.isArray(source.proxies)) {
    return source;
  }

  const decodedToken = decodeJwtPayload(source.id_token);
  const accountId = source.account_id ?? source.chatgpt_account_id ?? decodedToken?.['https://api.openai.com/auth']?.chatgpt_account_id ?? '';
  const planType = source.plan_type ?? source.chatgpt_plan_type ?? decodedToken?.['https://api.openai.com/auth']?.chatgpt_plan_type ?? 'plus';
  const email = source.email ?? decodedToken?.email ?? '';
  const account = source.account ?? buildDefaultAccount(accountId, planType);
  const credentials = {
    refresh_token: source.refresh_token ?? '',
    id_token: source.id_token ?? buildSyntheticIdToken(source),
    access_token: source.access_token ?? source.accessToken ?? '',
    session_token: source.session_token ?? source.sessionToken ?? '',
    chatgpt_account_id: accountId,
    email,
  };

  return {
    exported_at: nowIso(),
    proxies: Array.isArray(source.proxies) ? source.proxies : [],
    accounts: [
      {
        name: email || account.id || 'openai-account',
        platform: 'openai',
        type: 'oauth',
        credentials,
        extra: {
          load_factor: source.load_factor ?? source.extra?.load_factor ?? 10,
        },
        concurrency: source.concurrency ?? 10,
        priority: source.priority ?? 1,
        rate_multiplier: source.rate_multiplier ?? 1,
        auto_pause_on_expired: source.auto_pause_on_expired ?? true,
      },
    ],
  };
}

async function main() {
  const args = parseArgs(process.argv);
  if (args.help || !args.input || !args.output || !args.to) {
    process.stdout.write(`${usage()}\n`);
    process.exit(args.help ? 0 : 1);
  }

  if (!['codex', 'sub2api'].includes(args.to)) {
    throw new Error('Invalid --to value. Use codex or sub2api.');
  }

  const inputPath = path.resolve(args.input);
  const outputPath = path.resolve(args.output);
  const raw = await fs.readFile(inputPath, 'utf8');
  const parsed = JSON.parse(raw);
  const format = detectFormat(parsed);
  const converted = args.to === 'codex' ? toCodex(parsed) : toSub2Api(parsed);

  await fs.writeFile(outputPath, `${JSON.stringify(converted, null, 2)}\n`, 'utf8');
  process.stdout.write(`Converted ${format} -> ${args.to}: ${outputPath}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
