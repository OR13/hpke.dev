import type { Jwk } from "@hpke-jose";
import alicePrivate from "@/test-keys/alice.private.json";

export type TestKey = { name: string; privateKeyJwk: Jwk };

/**
 * Built-in throwaway keys, so the demo can decrypt shared/CLI-generated test
 * links with one click instead of uploading a private key file. These are the
 * same committed keys the CLI encrypts to (see `test-keys/`). Not secret.
 */
export const TEST_KEYS: TestKey[] = [
  { name: "alice", privateKeyJwk: alicePrivate as unknown as Jwk },
];
