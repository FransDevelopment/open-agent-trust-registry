import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { createHash, createHmac, createPrivateKey, createPublicKey, hkdfSync } from 'crypto';
import { getPublicKeyAsync } from '@noble/ed25519';
import { extract, expand } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

const document = readFileSync(resolve(__dirname, '../../../spec/10-encrypted-transport.md'), 'utf8');
const labels = ['All-zeros seed', 'All-ones seed', 'Counting seed', 'Random seed A', 'Random seed B'];
function section(text: string, heading: string): string {
  const start = text.indexOf(heading);
  if (start < 0) throw new Error(`Missing section: ${heading}`);
  return text.slice(start + heading.length).split(/\n#{3,4} /)[0];
}
function rows(text: string): string[][] {
  const table = section(text, '#### 2.3 Test Vectors');
  const result = table.split('\n').filter(line => /^\| /.test(line))
    .slice(1).map(line => line.split('|').slice(1, -1).map(cell => cell.trim()));
  if (result.length !== 5 || result.some(row => row.length !== 4) ||
      labels.some(label => result.filter(row => row[0] === label).length !== 1)) {
    throw new Error('Expected the five named transport rows');
  }
  return result;
}
function hex(value: string, bytes = 32): Buffer {
  const raw = value.replace(/^`([0-9a-fA-F]+)`$/, '$1');
  if (!new RegExp(`^[0-9a-fA-F]{${bytes * 2}}$`).test(raw)) {
    throw new Error(`Expected exact ${bytes}-byte hex: ${value}`);
  }
  return Buffer.from(raw, 'hex');
}
function nativePublic(seed: Buffer, kind: 'ed' | 'x'): Buffer {
  expect(seed.length).toBe(32);
  const scalar = kind === 'ed' ? seed : createHash('sha512').update(seed).digest().subarray(0, 32);
  if (kind === 'x') { scalar[0] &= 248; scalar[31] &= 127; scalar[31] |= 64; }
  const prefix = Buffer.from(kind === 'ed' ? '302e020100300506032b657004220420' :
    '302e020100300506032b656e04220420', 'hex');
  const key = createPrivateKey({ key: Buffer.concat([prefix, scalar]), format: 'der', type: 'pkcs8' });
  const der = createPublicKey(key).export({ format: 'der', type: 'spki' });
  expect(der.length).toBe(44);
  return der.subarray(-32);
}
async function checkRow(row: string[]): Promise<void> {
  const [seed, ed, x] = row.slice(1).map(value => hex(value));
  const nativeEd = nativePublic(seed, 'ed');
  const nativeX = nativePublic(seed, 'x');
  expect(Buffer.from(await getPublicKeyAsync(seed))).toEqual(nativeEd);
  expect({ ed: nativeEd.toString('hex'), x: nativeX.toString('hex') })
    .toEqual({ ed: ed.toString('hex'), x: x.toString('hex') });
}
function schedule(text: string): Record<string, Buffer> {
  const block = section(text, '#### 3.2 Invite Bootstrap')
    .match(/\*\*Test vector[^\n]*\n\s*```\n([\s\S]*?)```/)?.[1];
  if (!block) throw new Error('Missing HKDF vector');
  return Object.fromEntries(['invite_secret', 'invite_salt', 'conv_id', 'root_key', 'aead_key', 'nonce_key']
    .map(name => {
      const matches = [...block.matchAll(new RegExp(`^${name}:\\s*(\\S+)\\s*$`, 'gm'))];
      if (matches.length !== 1) throw new Error(`Missing or duplicate ${name}`);
      return [name, hex(matches[0][1], name === 'conv_id' ? 16 : 32)];
    }));
}
function checkSchedule(text: string): void {
  const v = schedule(text);
  const info = (name: string) => Buffer.concat([Buffer.from(`qntm/qsp/v1/${name}`), v.conv_id]);
  const prk = createHmac('sha256', v.invite_salt).update(v.invite_secret).digest();
  expect(Buffer.from(extract(sha256, v.invite_secret, v.invite_salt))).toEqual(prk);
  const root = Buffer.from(hkdfSync('sha256', v.invite_secret, v.invite_salt, info('root'), 32));
  expect(root).toEqual(v.root_key);
  expect(Buffer.from(expand(sha256, prk, info('root'), 32))).toEqual(root);
  for (const name of ['aead', 'nonce']) {
    // A 32-byte expansion is one HMAC block; subkeys expand root without another extract.
    const key = createHmac('sha256', root).update(info(name)).update(Buffer.from([1])).digest();
    expect(key.length).toBe(32);
    expect(key).toEqual(v[`${name}_key`]);
    expect(Buffer.from(expand(sha256, root, info(name), 32))).toEqual(key);
  }
}

describe('Published encrypted transport conformance', () => {
  it('requires the five named section 2.3 rows', () => { expect(rows(document)).toHaveLength(5); });
  for (const label of labels) {
    it(`reproduces ${label} with native keys and independent Noble Ed25519`, async () => {
      await checkRow(rows(document).find(row => row[0] === label)!);
    });
  }
  it('rejects missing sections, missing rows, duplicate labels and missing cells', () => {
    expect(() => rows(document.replace('#### 2.3 Test Vectors', '#### absent'))).toThrow();
    const row = rows(document)[0];
    expect(() => rows(document.replace(/^\| All-zeros seed.*\n/m, ''))).toThrow();
    expect(() => rows(document.replace('All-ones seed', row[0]))).toThrow();
    expect(() => rows(document.replace(`| ${row[3]} |`, '|'))).toThrow();
  });
  it('rejects malformed, abbreviated, odd-length and wrong-length hex', () => {
    for (const value of ['', 'gg'.repeat(32), '0'.repeat(63), '00'.repeat(31),
      '00'.repeat(33), '`0000...0000` (32 bytes)']) expect(() => hex(value)).toThrow();
  });
  it('passes RFC8032 test 1 and rejects corrupted expected Ed and X outputs', async () => {
    const seed = hex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
    const ed = hex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
    const row = ['RFC8032', seed.toString('hex'), ed.toString('hex'), nativePublic(seed, 'x').toString('hex')];
    await checkRow(row);
    for (const index of [2, 3]) {
      const corrupted = [...row];
      const value = hex(corrupted[index]); value[0] ^= 1;
      corrupted[index] = value.toString('hex');
      await expect(checkRow(corrupted)).rejects.toThrow();
    }
  });
  it('reproduces the published root and subkey schedule with Node and Noble', () => checkSchedule(document));
  it('rejects corrupted HKDF expected outputs and missing values', () => {
    for (const name of ['root_key', 'aead_key', 'nonce_key']) {
      const value = schedule(document)[name]; value[0] ^= 1;
      expect(() => checkSchedule(document.replace(schedule(document)[name].toString('hex'), value.toString('hex')))).toThrow();
    }
    expect(() => schedule(document.replace(/^conv_id:.*$/m, ''))).toThrow();
  });
});
