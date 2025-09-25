import { APIGatewayProxyEvent } from "aws-lambda";

export class AuthMiddleware {
  private requiredToken: string | undefined;

  constructor() {
    this.requiredToken = process.env.SIGNING_SERVER_TOKEN;
  }

  validateBearerToken(event: APIGatewayProxyEvent): void {
    // If no token is configured, allow all requests
    if (!this.requiredToken || this.requiredToken === "") {
      console.log("[Auth] No token configured, allowing request");
      return;
    }

    // Token is configured, so validate it
    const authHeader =
      event.headers["Authorization"] || event.headers["authorization"];

    if (!authHeader) {
      throw new UnauthorizedError("Missing Authorization header");
    }

    if (!authHeader.startsWith("Bearer ")) {
      throw new UnauthorizedError("Invalid Authorization header format");
    }

    const providedToken = authHeader.substring(7);

    if (providedToken !== this.requiredToken) {
      throw new UnauthorizedError("Invalid bearer token");
    }
  }
}

export class UnauthorizedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnauthorizedError";
  }
}
