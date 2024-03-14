import { RequestHandler as Middleware } from "express";
import { NotAuthorizedError } from "./error-handler";
import jsonwebtoken from "jsonwebtoken";
const tokens: string[] = [
  "auth",
  "seller",
  "gig",
  "search",
  "buyer",
  "message",
  "order",
  "review",
];

export const verifyGatewayRequest =
  (secret: string): Middleware =>
  (req, _res, next) => {
    if (!req.headers?.gatewaytoken) {
      throw new NotAuthorizedError(
        "Invalid request",
        "verifyGatewayRequest() method: Request not coming from api gateway"
      );
    }
    const token: string = req.headers?.gatewaytoken as string;
    if (!token) {
      throw new NotAuthorizedError(
        "Invalid request",
        "verifyGatewayRequest() method: Request not coming from api gateway"
      );
    }

    try {
      const payload: { id: string; iat: number } = jsonwebtoken.verify(
        token,
        secret
      ) as { id: string; iat: number };
      if (!tokens.includes(payload.id)) {
        throw new NotAuthorizedError(
          "Invalid request",
          "verifyGatewayRequest() method: Request payload is invalid"
        );
      }
    } catch (error) {
      throw new NotAuthorizedError(
        "Invalid request",
        "verifyGatewayRequest() method: Request not coming from api gateway"
      );
    }
    next();
  };
