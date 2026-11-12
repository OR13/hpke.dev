/** Draft-27: psk_id (-5) is protected; the PSK is supplied out of band. */
export interface PskOptions { psk?: Uint8Array; pskId?: Uint8Array }
export const HEADER_PSK_ID = -5;
export function senderPsk(options: PskOptions) {
  if (options.psk === undefined && options.pskId === undefined) return {};
  if (!(options.psk instanceof Uint8Array) || options.psk.length < 32 ||
      !(options.pskId instanceof Uint8Array) || options.pskId.length === 0) {
    throw new Error("PSK requires at least 32 bytes and a nonempty pskId");
  }
  return { psk: options.psk, pskId: options.pskId };
}
export function receiverPsk(protectedHeader: Map<number, unknown>, unprotected: Map<number, unknown>, options: PskOptions) {
  if (unprotected.has(HEADER_PSK_ID)) throw new Error("psk_id must be protected");
  const id = protectedHeader.get(HEADER_PSK_ID);
  if (!protectedHeader.has(HEADER_PSK_ID)) {
    if (options.psk !== undefined || options.pskId !== undefined) throw new Error("PSK supplied for base mode");
    return {};
  }
  if (!(id instanceof Uint8Array)) throw new Error("psk_id must be a byte string");
  if (options.pskId && (options.pskId.length !== id.length || options.pskId.some((b, i) => b !== id[i]))) {
    throw new Error("psk_id mismatch");
  }
  return senderPsk({ psk: options.psk, pskId: id });
}
