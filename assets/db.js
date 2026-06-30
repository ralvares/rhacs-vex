// DuckDB WASM initialization and query helpers
import * as duckdb from 'https://cdn.jsdelivr.net/npm/@duckdb/duckdb-wasm@1.29.0/+esm';

let db = null;
let conn = null;
const registered = new Set();

export async function initDuckDB(onStatus) {
  onStatus?.('Loading DuckDB…');
  const bundles = duckdb.getJsDelivrBundles();
  const bundle  = await duckdb.selectBundle(bundles);
  const wkUrl   = URL.createObjectURL(
    new Blob([`importScripts("${bundle.mainWorker}");`], { type: 'text/javascript' })
  );
  db = new duckdb.AsyncDuckDB(new duckdb.ConsoleLogger(), new Worker(wkUrl));
  await db.instantiate(bundle.mainModule, bundle.pthreadWorker);
  URL.revokeObjectURL(wkUrl);
  conn = await db.connect();
  onStatus?.('DuckDB ready', 'ready');
  return { db, conn };
}

export async function loadManifest(path = 'data/manifest.json') {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`Failed to load manifest: HTTP ${res.status}`);
  return res.json();
}

export function resolveScopes(manifest, pattern) {
  const scopes = manifest.scopes || {};
  if (pattern.includes('*')) {
    const prefix = pattern.replace('*', '');
    return Object.keys(scopes).filter(k => k.startsWith(prefix));
  }
  return scopes[pattern] ? [pattern] : [];
}

export function safeName(scopeKey) {
  return scopeKey.replace(/[^a-zA-Z0-9_]/g, '_') + '.parquet';
}

export async function registerScope(manifest, scopeKey) {
  const name = safeName(scopeKey);
  if (registered.has(name)) return name;
  const entry = (manifest.scopes || {})[scopeKey];
  if (!entry) throw new Error(`Scope not found: ${scopeKey}`);
  const url = new URL(entry.file, window.location.href).href;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch ${entry.file}: HTTP ${res.status}`);
  try { await db.dropFile(name); } catch {}
  await db.registerFileBuffer(name, new Uint8Array(await res.arrayBuffer()));
  registered.add(name);
  return name;
}

export async function registerScopes(manifest, pattern) {
  const keys = resolveScopes(manifest, pattern);
  const names = await Promise.all(keys.map(k => registerScope(manifest, k)));
  return names;
}

export async function query(sql) {
  if (!conn) throw new Error('DuckDB not initialized');
  const result = await conn.query(sql);
  return result.toArray().map(r => ({ ...r }));
}

export async function queryFromScopes(scopeKeys, sql) {
  if (!scopeKeys.length) return [];
  const files = scopeKeys.map(k => `'${k}'`).join(', ');
  const fullSql = sql.replace('__FILES__', `read_parquet([${files}])`);
  return query(fullSql);
}

export async function registerFileByURL(name, url) {
  if (registered.has(name)) return;
  if (!db) throw new Error('DuckDB not initialized');
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch ${url}: HTTP ${res.status}`);
  try { await db.dropFile(name); } catch {}
  await db.registerFileBuffer(name, new Uint8Array(await res.arrayBuffer()));
  registered.add(name);
}

export async function registerCveIndex(path = 'data/parquet/cve-index.parquet') {
  if (registered.has('cve_index.parquet')) return;
  if (!db) throw new Error('DuckDB not initialized');
  const url = new URL(path, window.location.href).href;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch cve-index: HTTP ${res.status}`);
  try { await db.dropFile('cve_index.parquet'); } catch {}
  await db.registerFileBuffer('cve_index.parquet', new Uint8Array(await res.arrayBuffer()));
  registered.add('cve_index.parquet');
}

export function clearRegistered() { registered.clear(); }
export function getDB() { return db; }
export function getConn() { return conn; }
