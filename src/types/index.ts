export interface C2PASigningRequest {
  claim: string;
}

export interface C2PASigningResponse {
  signature: string;
}

export interface CertificateSigningRequest {
  csr: string;
}

export interface SignedCertificateResponse {
  certificate_id: string;
  certificate_chain: string;
  expires_at: Date;
  serial_number: string;
}

export interface C2PAConfiguration {
  algorithm: string;
  timestamp_url: string;
  signing_url: string;
  certificate_chain: string;
  // Legacy fields (optional for backward compatibility)
  supportedAlgorithms?: string[];
  maxManifestSize?: number;
  version?: string;
}

export interface HealthCheckResponse {
  status: string;
  version: string;
  mode: string;
  c2pa_version: string;
}
