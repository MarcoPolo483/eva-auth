import { AuthError } from "../util/errors.js";

import type { ValidationOptions } from "./validator.js";
import { validateToken } from "./validator.js";


export type RequestLike = { headers: Record<string, string | string[] | undefined>; user?: any };
export type ResponseLike = { statusCode?: number; end?: (body?: any) => void };
export type NextLike = (err?: any) => void;

export function authMiddleware(opts: ValidationOptions) {
  return async (req: RequestLike, res: ResponseLike, next: NextLike) => {
    try {
      const auth = header(req.headers, "authorization");
      if (!auth || !auth.startsWith("Bearer ")) {
        throw new AuthError("Missing bearer token");
      }
      const token = auth.substring("Bearer ".length);
      const validated = await validateToken(token, opts);
      req.user = validated.payload;
      next();
    } catch (e: any) {
      res.statusCode = 401;
      res.end?.(JSON.stringify({ error: e.code || "UNAUTH", message: e.message }));
    }
  };
}

function header(headers: Record<string, string | string[] | undefined>, key: string): string | undefined {
  const v = headers[key] ?? headers[key.toLowerCase()];
  if (Array.isArray(v)) return v[0];
  return v;
}