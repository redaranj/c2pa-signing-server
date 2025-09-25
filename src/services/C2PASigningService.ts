import { KMSSigningService } from "./KMSSigningService";
import { SecretsManagerService } from "./SecretsManagerService";
import { CryptoUtils } from "../utils/crypto";
import { C2PASigningRequest, C2PASigningResponse } from "../types";
// TODO: Import c2pa-node-v2 once it's properly built with Rust
// import { Builder, CallbackSigner, LocalSigner } from "@contentauth/c2pa-node";

export class C2PASigningService {
  private kmsService: KMSSigningService;
  private secretsManager: SecretsManagerService;

  constructor() {
    this.kmsService = new KMSSigningService();
    this.secretsManager = new SecretsManagerService();
  }

  async getCertificateChain(): Promise<string> {
    // Get the certificate chain and return it base64 encoded
    const credentials = await this.getLocalSigningCredentials();
    const certChainBuffer = Buffer.from(credentials.certificateChain);
    return certChainBuffer.toString("base64");
  }

  async signManifest(
    request: C2PASigningRequest,
  ): Promise<C2PASigningResponse> {
    console.log("[C2PA Service] Received signing request");

    try {
      const dataToSign = CryptoUtils.base64Decode(request.claim);
      console.log(
        `[C2PA Service] Data to sign size: ${dataToSign.length} bytes`,
      );

      let signature: string;

      if (process.env.USE_KMS === "true") {
        console.log("[C2PA Service] Using KMS for signing");
        signature = await this.kmsService.signWithKMS(dataToSign);
      } else {
        console.log("[C2PA Service] Using local key for signing");
        const credentials = await this.getLocalSigningCredentials();

        if (!credentials.privateKey) {
          throw new Error("Private key not available for local signing");
        }

        signature = await this.kmsService.signWithLocalKey(
          dataToSign,
          credentials.privateKey,
        );
      }

      console.log(
        `[C2PA Service] Signature generated, size: ${Buffer.from(signature, "base64").length} bytes`,
      );

      return {
        signature,
      };
    } catch (error) {
      console.error("[C2PA Service] Signing failed:", error);
      throw new Error(
        `C2PA signing failed: ${error instanceof Error ? error.message : "Unknown error"}`,
      );
    }
  }

  private async getLocalSigningCredentials() {
    if (process.env.USE_AWS_SECRETS === "true") {
      return await this.secretsManager.getSigningCredentials();
    }

    // Use the es256 files from the repository root
    const fs = await import("fs").then((m) => m.promises);
    const path = await import("path");

    const certPath = path.join(process.cwd(), "es256_certs.pem");
    const keyPath = path.join(process.cwd(), "es256_private.key");

    try {
      const certificateChain = await fs.readFile(certPath, "utf8");
      const privateKey = await fs.readFile(keyPath, "utf8");

      console.log("[C2PA Service] Loaded es256 certificates from files");

      return {
        certificateChain,
        privateKey,
      };
    } catch (error) {
      console.error("[C2PA Service] Error loading certificates:", error);
      throw new Error("Failed to load signing certificates from files");
    }
  }
}
