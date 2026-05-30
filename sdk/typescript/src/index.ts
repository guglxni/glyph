export { GlyphClient } from './client';
export { IntentBuilder } from './intent';
export type { BuildOptions } from './intent';

export {
  Groth16Proof,
  GlyphError,
  groth16ProofFromHex,
  groth16ProofToHex,
  toAccountMeta,
  fromAccountMeta,
  workerCodeToKind,
} from './types';
export type {
  TransactionIntent,
  IntentAction,
  IntentConstraints,
  AccountMeta,
  AccountMetaCamel,
  ActionType,
  CanonicalIntent,
  CanonicalAccountMeta,
  PublicInputs,
  GlyphProofBundle,
  GlyphClientConfig,
  GlyphErrorKind,
  MtlsClientHandle,
  WorkerResponse,
  WorkerResponseSuccess,
  WorkerResponseError,
} from './types';

export {
  canonicalSigningPayload,
  canonicalTargetInstructionBytes,
  hashSigningPayload,
  hashTargetInstruction,
  bytesToHex,
  hexToBytes,
} from './canonical';
