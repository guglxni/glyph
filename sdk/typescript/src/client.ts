import { Connection } from '@solana/web3.js';
import { Socket } from 'net';

import { IntentBuilder } from './intent';
import {
  GlyphClientConfig,
  GlyphError,
  GlyphProofBundle,
  Groth16Proof,
  MtlsClientHandle,
  PublicInputs,
  TransactionIntent,
  WorkerResponse,
  workerCodeToKind,
} from './types';
import { hexToBytes } from './canonical';

const DEFAULT_TIMEOUT_MS = 15_000;

// Strict regex parser for `tcp://host:port` and `mtls://host:port`. Refuses
// missing port, empty host, or anything `new URL()` would silently accept
// for non-standard schemes (closes F-13).
const TRANSPORT_REGEX = /^(tcp|mtls):\/\/([A-Za-z0-9._-]+|\[[0-9a-fA-F:]+\]):(\d+)$/;

const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', '0.0.0.0', 'localhost']);

interface ParsedEndpoint {
  scheme: 'tcp' | 'mtls';
  host: string;
  port: number;
}

function parseEndpoint(endpoint: string): ParsedEndpoint {
  const match = TRANSPORT_REGEX.exec(endpoint);
  if (!match) {
    if (/^https?:\/\//i.test(endpoint)) {
      throw new GlyphError(
        'InvalidEndpoint',
        `http(s):// endpoints are not supported (no HTTP transport implemented). ` +
          `Use tcp://host:port or mtls://host:port.`,
      );
    }
    throw new GlyphError(
      'InvalidEndpoint',
      `Invalid teeEndpoint "${endpoint}". Expected tcp://host:port or mtls://host:port.`,
    );
  }
  const scheme = match[1] as 'tcp' | 'mtls';
  let host = match[2];
  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.slice(1, -1);
  }
  const port = Number.parseInt(match[3], 10);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new GlyphError(
      'InvalidEndpoint',
      `Invalid port "${match[3]}" in endpoint ${endpoint}`,
    );
  }
  return { scheme, host, port };
}

function maybeWarnLoopback(host: string): void {
  if (
    process.env.NODE_ENV === 'production' &&
    LOOPBACK_HOSTS.has(host.toLowerCase())
  ) {
    // eslint-disable-next-line no-console
    console.warn(
      `[GlyphClient] WARNING: teeEndpoint resolves to loopback host "${host}" ` +
        `with NODE_ENV=production. This is almost certainly a misconfiguration ` +
        `and means traffic is going to a local mock worker instead of a real TEE.`,
    );
  }
}

// ─── Worker response coercion ─────────────────────────────────────────────────

function coerceUint8(value: unknown, name: string): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return Uint8Array.from(value as number[]);
  if (typeof value === 'string') return hexToBytes(value);
  throw new GlyphError(
    'WorkerProtocolError',
    `Worker response field ${name} has unsupported type ${typeof value}`,
  );
}

function coerceProofBundle(raw: unknown): GlyphProofBundle {
  if (!raw || typeof raw !== 'object') {
    throw new GlyphError('WorkerProtocolError', 'Worker bundle is not an object');
  }
  const obj = raw as Record<string, unknown>;
  const proofObj = obj.proof as Record<string, unknown> | undefined;
  if (!proofObj) {
    throw new GlyphError('WorkerProtocolError', 'Worker bundle missing `proof`');
  }
  const piObj = obj.public_inputs as Record<string, unknown> | undefined;
  if (!piObj) {
    throw new GlyphError(
      'WorkerProtocolError',
      'Worker bundle missing `public_inputs`',
    );
  }

  const proof = new Groth16Proof({
    a: coerceUint8(proofObj.a, 'proof.a'),
    b: coerceUint8(proofObj.b, 'proof.b'),
    c: coerceUint8(proofObj.c, 'proof.c'),
  });

  const publicInputs: PublicInputs = {
    policy_commitment: coerceUint8(piObj.policy_commitment, 'public_inputs.policy_commitment'),
    intent_hash: coerceUint8(piObj.intent_hash, 'public_inputs.intent_hash'),
    agent_pubkey: coerceUint8(piObj.agent_pubkey, 'public_inputs.agent_pubkey'),
    nonce: coerceUint8(piObj.nonce, 'public_inputs.nonce'),
    tx_hash: coerceUint8(piObj.tx_hash, 'public_inputs.tx_hash'),
  };

  const signedTx = coerceUint8(obj.signed_transaction, 'signed_transaction');
  const txHashPrefix = coerceUint8(obj.tx_hash_prefix, 'tx_hash_prefix');
  if (txHashPrefix.length !== 16) {
    throw new GlyphError(
      'WorkerProtocolError',
      `tx_hash_prefix must be 16 bytes, got ${txHashPrefix.length}`,
    );
  }

  return {
    proof,
    public_inputs: publicInputs,
    signed_transaction: signedTx,
    tx_hash_prefix: txHashPrefix,
  };
}

function validateWorkerResponse(value: unknown): WorkerResponse {
  if (!value || typeof value !== 'object') {
    throw new GlyphError(
      'WorkerProtocolError',
      'Worker response is not an object',
    );
  }
  const obj = value as Record<string, unknown>;
  if (obj.status === 'success') {
    return { status: 'success', bundle: coerceProofBundle(obj.bundle) };
  }
  if (obj.status === 'error') {
    return {
      status: 'error',
      code: typeof obj.code === 'string' ? obj.code : undefined,
      message: typeof obj.message === 'string' ? obj.message : undefined,
    };
  }
  throw new GlyphError(
    'WorkerProtocolError',
    `Worker response has invalid status field: ${String(obj.status)}`,
  );
}

// ─── GlyphClient ──────────────────────────────────────────────────────────────

export class GlyphClient {
  private readonly connection: Connection;

  private readonly endpoint: ParsedEndpoint;

  private readonly endpointRaw: string;

  private readonly agentKeypair: GlyphClientConfig['agentKeypair'];

  private readonly mtlsClient?: MtlsClientHandle;

  private readonly timeoutMs: number;

  constructor(config: GlyphClientConfig) {
    if (!config.teeEndpoint) {
      throw new GlyphError('InvalidEndpoint', 'GlyphClient requires a teeEndpoint');
    }

    this.endpoint = parseEndpoint(config.teeEndpoint);
    this.endpointRaw = config.teeEndpoint;
    maybeWarnLoopback(this.endpoint.host);

    this.connection = config.connection;
    this.agentKeypair = config.agentKeypair;
    this.mtlsClient = config.mtlsClient;
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  buildIntent(): IntentBuilder {
    return new IntentBuilder();
  }

  getAgentPublicKey(): string {
    return this.agentKeypair.publicKey.toBase58();
  }

  async execute(intent: TransactionIntent): Promise<GlyphProofBundle> {
    let response: WorkerResponse;
    try {
      if (this.endpoint.scheme === 'tcp') {
        response = await this.sendTcpRequest(intent);
      } else {
        response = await this.sendMtlsRequest(intent);
      }
    } catch (error) {
      if (error instanceof GlyphError) throw error;
      const message = error instanceof Error ? error.message : String(error);
      // Heuristics for common Node net errors.
      let kind: GlyphError['kind'] = 'Unknown';
      if (/ECONNREFUSED/i.test(message)) kind = 'ConnectionRefused';
      else if (/ETIMEDOUT|timed out/i.test(message)) kind = 'ConnectionRefused';
      throw new GlyphError(
        kind,
        `Failed communicating with TEE worker at ${this.endpointRaw}: ${message}`,
      );
    }

    if (response.status === 'success') {
      return response.bundle;
    }

    const kind = workerCodeToKind(response.code);
    const message =
      response.message ?? `Worker returned ${response.code ?? 'an unspecified error'}`;
    throw new GlyphError(kind, message, response.code);
  }

  async submitTransaction(bundle: GlyphProofBundle): Promise<string> {
    try {
      const rawTx = Buffer.from(bundle.signed_transaction);
      const signature = await this.connection.sendRawTransaction(rawTx);
      await this.connection.confirmTransaction(signature);
      return signature;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new GlyphError(
        'Unknown',
        `Failed to submit signed transaction to Solana: ${message}`,
      );
    }
  }

  private async sendMtlsRequest(intent: TransactionIntent): Promise<WorkerResponse> {
    if (!this.mtlsClient) {
      throw new GlyphError(
        'TransportNotImplemented',
        `mtls:// endpoint requires an mtlsClient transport. Pass GlyphClientConfig.mtlsClient ` +
          `(see WS-5). Native mTLS is not yet implemented.`,
      );
    }
    const payload = new TextEncoder().encode(JSON.stringify(intent));
    const responseBytes = await this.mtlsClient.send(payload);
    const text = new TextDecoder().decode(responseBytes);
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new GlyphError('WorkerProtocolError', `Invalid mTLS response JSON: ${message}`);
    }
    return validateWorkerResponse(parsed);
  }

  private sendTcpRequest(intent: TransactionIntent): Promise<WorkerResponse> {
    return new Promise((resolve, reject) => {
      const socket = new Socket();
      const chunks: Buffer[] = [];

      const onError = (error: Error): void => {
        socket.destroy();
        reject(error);
      };

      socket.setTimeout(this.timeoutMs, () => {
        onError(new Error('TCP request timed out'));
      });

      socket.on('error', onError);
      socket.on('data', (chunk: Buffer) => {
        chunks.push(chunk);
      });
      socket.on('end', () => {
        try {
          const payload = Buffer.concat(chunks).toString('utf-8');
          if (!payload) {
            throw new GlyphError(
              'WorkerProtocolError',
              'TEE worker returned an empty TCP response',
            );
          }
          const parsed = JSON.parse(payload) as unknown;
          resolve(validateWorkerResponse(parsed));
        } catch (error) {
          if (error instanceof GlyphError) {
            reject(error);
            return;
          }
          const message = error instanceof Error ? error.message : String(error);
          reject(
            new GlyphError(
              'WorkerProtocolError',
              `Invalid TCP response payload: ${message}`,
            ),
          );
        } finally {
          socket.destroy();
        }
      });

      socket.connect(this.endpoint.port, this.endpoint.host, () => {
        socket.end(JSON.stringify(intent));
      });
    });
  }
}
