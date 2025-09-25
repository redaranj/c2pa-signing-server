import * as crypto from 'crypto';

export class CryptoUtils {
  static async signDataWithECDSA(data: Buffer, privateKeyPEM: string): Promise<Buffer> {
    const sign = crypto.createSign('SHA256');
    sign.update(data);
    sign.end();
    return sign.sign(privateKeyPEM);
  }

  static extractPrivateKeyFromPEM(pemContent: string): string {
    const privateKeyMatch = pemContent.match(
      /-----BEGIN (EC PRIVATE KEY|PRIVATE KEY)-----[\s\S]+?-----END (EC PRIVATE KEY|PRIVATE KEY)-----/
    );
    if (!privateKeyMatch) {
      throw new Error('Invalid private key format');
    }
    return privateKeyMatch[0];
  }

  static extractCertificateChainFromPEM(pemContent: string): string[] {
    const certificates: string[] = [];
    const certMatches = pemContent.matchAll(
      /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g
    );

    for (const match of certMatches) {
      certificates.push(match[0]);
    }

    if (certificates.length === 0) {
      throw new Error('No certificates found in PEM content');
    }

    return certificates;
  }

  static base64Encode(buffer: Buffer): string {
    return buffer.toString('base64');
  }

  static base64Decode(base64String: string): Buffer {
    return Buffer.from(base64String, 'base64');
  }
}