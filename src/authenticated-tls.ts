/** Authenticated TLS 1.3 through the maintained Node/OpenSSL implementation. */
import { connect, createServer, type TLSSocket, type Server, type SecureContextOptions } from 'node:tls';

export const AUTHENTICATED_HYBRID_GROUP = 'X25519MLKEM768';
export const AUTHENTICATED_HYBRID_CIPHER = 'TLS_AES_256_GCM_SHA384';

export interface AuthenticatedHybridClientOptions {
  readonly host: string;
  readonly port: number;
  readonly servername: string;
  readonly ca?: SecureContextOptions['ca'];
  readonly timeoutMs?: number;
}
export interface AuthenticatedHybridServerOptions {
  readonly key: NonNullable<SecureContextOptions['key']>;
  readonly cert: NonNullable<SecureContextOptions['cert']>;
}

/** Resolves only after certificate/hostname validation and strict hybrid TLS negotiation. */
export function connectAuthenticatedHybridTls(options: AuthenticatedHybridClientOptions): Promise<TLSSocket> {
  const timeoutMs = options?.timeoutMs ?? 10000;
  if (!options || typeof options.host !== 'string' || !options.host ||
      typeof options.servername !== 'string' || !options.servername.trim() ||
      !Number.isInteger(options.port) || options.port < 1 || options.port > 65535 ||
      !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000) {
    throw new Error('INVALID_AUTHENTICATED_TLS_OPTIONS: Require host, port, expected servername and a bounded timeout');
  }
  return new Promise((resolve, reject) => {
    // Deliberately select fields instead of spreading caller-supplied TLS options.
    // Certificate checks, version, cipher and group cannot be disabled by extra properties.
    const socket = connect({ host: options.host, port: options.port, servername: options.servername,
      ca: options.ca, rejectUnauthorized: true, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3',
      ecdhCurve: AUTHENTICATED_HYBRID_GROUP, ciphers: AUTHENTICATED_HYBRID_CIPHER });
    const timer = setTimeout(() => socket.destroy(new Error('TLS_HANDSHAKE_TIMEOUT')), timeoutMs);
    const onError = (error: Error) => { clearTimeout(timer); socket.removeListener('secureConnect', onSecure); socket.destroy(); reject(error); };
    const onSecure = () => {
      const group = socket.getEphemeralKeyInfo();
      const groupName = group && 'name' in group ? group.name : undefined;
      if (!socket.authorized || socket.getProtocol() !== 'TLSv1.3' ||
          groupName !== AUTHENTICATED_HYBRID_GROUP || socket.getCipher().standardName !== AUTHENTICATED_HYBRID_CIPHER) {
        socket.destroy(new Error('HYBRID_TLS_NEGOTIATION_FAILED: Required authenticated hybrid TLS 1.3'));
        return;
      }
      clearTimeout(timer); socket.removeListener('error', onError); resolve(socket);
    };
    socket.once('error', onError); socket.once('secureConnect', onSecure);
  });
}

/** Server-authenticated TLS; this API does not claim mutual/client-certificate authentication. */
export function createAuthenticatedHybridTlsServer(
  options: AuthenticatedHybridServerOptions,
  listener?: (socket: TLSSocket) => void
): Server {
  if (!options?.key || !options?.cert) throw new Error('MISSING_TLS_IDENTITY: Server key and certificate required');
  return createServer({ key: options.key, cert: options.cert,
    minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', ecdhCurve: AUTHENTICATED_HYBRID_GROUP,
    ciphers: AUTHENTICATED_HYBRID_CIPHER, handshakeTimeout: 10000 }, listener);
}
