export function ab2hex(ab: ArrayBuffer): string {
  return [...new Uint8Array(ab)].map(x => x.toString(16).padStart(2, '0')).join('');
}

export function hex2ab(hex: string): ArrayBuffer {
  const view = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    view[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return view.buffer;
}

export async function hashPassword(password: string, salt?: Uint8Array): Promise<{ hash: string, salt: string }> {
  const saltBuffer = salt || crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBuffer,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  );
  return {
    hash: ab2hex(derivedBits),
    salt: ab2hex(saltBuffer),
  };
}

export async function verifyPassword(password: string, hash: string, salt: string): Promise<boolean> {
  const { hash: newHash } = await hashPassword(password, new Uint8Array(hex2ab(salt)));
  return newHash === hash;
}