import { KMSClient, SignCommand, SignCommandInput } from '@aws-sdk/client-kms';
import { CryptoUtils } from '../utils/crypto';

export class KMSSigningService {
  private kmsClient: KMSClient;
  private keyId?: string;

  constructor(region: string = process.env.AWS_REGION || 'us-east-1') {
    this.kmsClient = new KMSClient({ region });
    this.keyId = process.env.KMS_KEY_ID;
  }

  async signWithKMS(data: Buffer): Promise<string> {
    if (!this.keyId) {
      throw new Error('KMS_KEY_ID environment variable is not set');
    }

    const params: SignCommandInput = {
      KeyId: this.keyId,
      Message: data,
      SigningAlgorithm: 'ECDSA_SHA_256',
      MessageType: 'RAW'
    };

    try {
      const command = new SignCommand(params);
      const response = await this.kmsClient.send(command);

      if (!response.Signature) {
        throw new Error('KMS signing failed: no signature returned');
      }

      return CryptoUtils.base64Encode(Buffer.from(response.Signature));
    } catch (error) {
      console.error('KMS signing error:', error);
      throw new Error(`KMS signing failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async signWithLocalKey(data: Buffer, privateKeyPEM: string): Promise<string> {
    try {
      const signature = await CryptoUtils.signDataWithECDSA(data, privateKeyPEM);
      return CryptoUtils.base64Encode(signature);
    } catch (error) {
      console.error('Local signing error:', error);
      throw new Error(`Local signing failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}