import * as crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { SignedCertificateResponse } from '../types';
import { SecretsManagerService } from './SecretsManagerService';

export class CertificateService {
  private secretsManager: SecretsManagerService;

  constructor() {
    this.secretsManager = new SecretsManagerService();
  }

  async signCSR(csrPEM: string): Promise<SignedCertificateResponse> {
    if (!csrPEM.includes('BEGIN CERTIFICATE REQUEST')) {
      throw new Error('Invalid CSR format');
    }

    try {
      const caCredentials = await this.getCACredentials();

      const serialNumber = this.generateSerialNumber();
      const expiresAt = new Date();
      expiresAt.setFullYear(expiresAt.getFullYear() + 1);

      const certificateChain = await this.generateCertificateChain(
        csrPEM,
        caCredentials,
        serialNumber,
        expiresAt
      );

      return {
        certificate_id: uuidv4(),
        certificate_chain: certificateChain,
        expires_at: expiresAt,
        serial_number: serialNumber
      };
    } catch (error) {
      console.error('CSR signing failed:', error);
      throw new Error(`Failed to sign CSR: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async getCACredentials(): Promise<any> {
    if (process.env.USE_AWS_SECRETS === 'true') {
      return await this.secretsManager.getCertificateAuthorityCredentials();
    }

    return this.generateTestCACredentials();
  }

  private generateTestCACredentials(): any {
    const rootKeyPair = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    const intermediateKeyPair = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    return {
      rootCA: this.generateSelfSignedCertificate('C2PA Test Root CA', rootKeyPair),
      rootCAPrivateKey: rootKeyPair.privateKey,
      intermediateCA: this.generateSelfSignedCertificate('C2PA Test Intermediate CA', intermediateKeyPair),
      intermediateCAPrivateKey: intermediateKeyPair.privateKey
    };
  }

  private generateSelfSignedCertificate(commonName: string, keyPair: crypto.KeyPairSyncResult<string, string>): string {
    const cert = `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHZ8Z3Y5Z3YMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNVBAYTAlVT
MRMwEQYDVQQIDApDYWxpZm9ybmlhMSEwHwYDVQQKDBhDMlBBIFNpZ25pbmcgU2Vy
dmVyIFRlc3QwHhcNMjQwMTAxMDAwMDAwWhcNMzQwMTAxMDAwMDAwWjBFMQswCQYD
VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEhMB8GA1UECgwYQzJQQSBTaWdu
aW5nIFNlcnZlciBUZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE${commonName}
-----END CERTIFICATE-----`;
    return cert;
  }

  private async generateCertificateChain(
    csrPEM: string,
    caCredentials: any,
    serialNumber: string,
    expiresAt: Date
  ): Promise<string> {
    const signedCert = this.mockSignCertificate(csrPEM, caCredentials, serialNumber, expiresAt);

    const certificateChain = [
      signedCert,
      caCredentials.intermediateCA,
      caCredentials.rootCA
    ].join('\n');

    return certificateChain;
  }

  private mockSignCertificate(
    csrPEM: string,
    caCredentials: any,
    serialNumber: string,
    expiresAt: Date
  ): string {
    const cert = `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJA${serialNumber}MA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNVBAYTAlVT
MRMwEQYDVQQIDApDYWxpZm9ybmlhMSEwHwYDVQQKDBhDMlBBIFNpZ25pbmcgU2Vy
dmVyIFRlc3QwHhcNMjQwMTAxMDAwMDAwWhcN${expiresAt.toISOString()}WjBFMQswCQYD
VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEhMB8GA1UECgwYQzJQQSBTaWdu
aW5nIFNlcnZlciBUZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESignedCert
-----END CERTIFICATE-----`;
    return cert;
  }

  private generateSerialNumber(): string {
    return crypto.randomBytes(8).toString('hex').toUpperCase();
  }
}