import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';

export interface SigningCredentials {
  certificateChain: string;
  privateKey?: string;
}

export class SecretsManagerService {
  private client: SecretsManagerClient;

  constructor(region: string = process.env.AWS_REGION || 'us-east-1') {
    this.client = new SecretsManagerClient({ region });
  }

  async getSigningCredentials(secretName?: string): Promise<SigningCredentials> {
    const resolvedSecretName = secretName || process.env.SIGNING_CREDENTIALS_SECRET || 'c2pa-signing-credentials';

    try {
      const command = new GetSecretValueCommand({
        SecretId: resolvedSecretName
      });

      const response = await this.client.send(command);

      if (!response.SecretString) {
        throw new Error('Secret value is empty');
      }

      const secret = JSON.parse(response.SecretString);

      if (!secret.certificateChain) {
        throw new Error('Certificate chain not found in secret');
      }

      return {
        certificateChain: secret.certificateChain,
        privateKey: secret.privateKey
      };
    } catch (error) {
      console.error('Failed to retrieve signing credentials:', error);
      throw new Error(`Failed to get signing credentials: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async getCertificateAuthorityCredentials(secretName?: string): Promise<SigningCredentials> {
    const resolvedSecretName = secretName || process.env.CA_CREDENTIALS_SECRET || 'c2pa-ca-credentials';

    try {
      const command = new GetSecretValueCommand({
        SecretId: resolvedSecretName
      });

      const response = await this.client.send(command);

      if (!response.SecretString) {
        throw new Error('Secret value is empty');
      }

      const secret = JSON.parse(response.SecretString);

      if (!secret.rootCA || !secret.rootCAPrivateKey || !secret.intermediateCA || !secret.intermediateCAPrivateKey) {
        throw new Error('CA credentials incomplete in secret');
      }

      return secret;
    } catch (error) {
      console.error('Failed to retrieve CA credentials:', error);
      throw new Error(`Failed to get CA credentials: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}