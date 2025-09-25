import {
  APIGatewayProxyHandler,
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Context,
} from "aws-lambda";
import { C2PASigningService } from "../services/C2PASigningService";
import { CertificateService } from "../services/CertificateService";
import {
  AuthMiddleware,
  UnauthorizedError,
} from "../middleware/authMiddleware";
import {
  C2PASigningRequest,
  CertificateSigningRequest,
  C2PAConfiguration,
  HealthCheckResponse,
} from "../types";

const c2paService = new C2PASigningService();
const certificateService = new CertificateService();
const authMiddleware = new AuthMiddleware();

const createResponse = (
  statusCode: number,
  body: any,
): APIGatewayProxyResult => ({
  statusCode,
  headers: {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  },
  body: JSON.stringify(body),
});

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent,
  context: Context,
): Promise<APIGatewayProxyResult> => {
  console.log(`[Lambda] Received request: ${event.httpMethod} ${event.path}`);

  if (event.httpMethod === "OPTIONS") {
    return createResponse(200, {});
  }

  try {
    // Remove /dev prefix if present (added by serverless offline)
    const path = event.path.replace(/^\/dev/, "") || "/";

    if (path === "/" && event.httpMethod === "GET") {
      const response: HealthCheckResponse = {
        status: "C2PA Signing Server is running",
        version: "1.0.0",
        mode: process.env.ENVIRONMENT || "production",
        c2pa_version: "1.0.0",
      };
      return createResponse(200, response);
    }

    if (path === "/health" && event.httpMethod === "GET") {
      return createResponse(200, { status: "healthy" });
    }

    if (path === "/api/v1/certificates/sign" && event.httpMethod === "POST") {
      if (!event.body) {
        return createResponse(400, { error: "Request body is required" });
      }

      const request: CertificateSigningRequest = JSON.parse(event.body);
      const response = await certificateService.signCSR(request.csr);
      return createResponse(200, response);
    }

    if (path.startsWith("/api/v1/c2pa/")) {
      try {
        authMiddleware.validateBearerToken(event);
      } catch (error) {
        if (error instanceof UnauthorizedError) {
          return createResponse(401, { error: error.message });
        }
        throw error;
      }

      if (path === "/api/v1/c2pa/configuration" && event.httpMethod === "GET") {
        // Get the signing server URL from environment or use request origin
        const signingServerUrl =
          process.env.SIGNING_SERVER_URL ||
          (event.headers["Host"]
            ? `https://${event.headers["Host"]}`
            : "http://localhost:3000");

        // Get certificate chain
        const certificateChain = await c2paService.getCertificateChain();

        const configuration: C2PAConfiguration = {
          algorithm: "es256",
          timestamp_url: "http://timestamp.digicert.com",
          signing_url: `https://air.tiger-agama.ts.net/dev/api/v1/c2pa/sign/`, // `${signingServerUrl}/dev/api/v1/c2pa/sign`,
          certificate_chain: certificateChain,
        };

        console.log(
          `[Lambda] Configuration: signingURL=${configuration.signing_url}`,
        );
        return createResponse(200, configuration);
      }

      if (path === "/api/v1/c2pa/sign" && event.httpMethod === "POST") {
        if (!event.body) {
          return createResponse(400, { error: "Request body is required" });
        }

        const request: C2PASigningRequest = JSON.parse(event.body);
        const response = await c2paService.signManifest(request);
        return createResponse(200, response);
      }
    }

    return createResponse(404, { error: "Not found" });
  } catch (error) {
    console.error("[Lambda] Error processing request:", error);

    if (error instanceof SyntaxError) {
      return createResponse(400, { error: "Invalid JSON in request body" });
    }

    const errorMessage =
      error instanceof Error ? error.message : "Internal server error";
    return createResponse(500, { error: errorMessage });
  }
};
