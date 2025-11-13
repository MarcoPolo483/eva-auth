# eva-auth (Enterprise Edition)

Authentication & authorization for EVA 2.0:
- Azure Entra ID (Microsoft Identity Platform) JWT validation (RS256 via JWKS)
- Audience and tenant enforcement
- Role extraction and mapping (supports array or delimited string)
- Express-style middleware (framework agnostic pattern)
- Enterprise toolchain: ESLint v9 flat config, Prettier, Vitest coverage thresholds, Husky + lint-staged

## Environment Variables (recommended)
- AUTH_TENANT_ID = <Entra tenant GUID>
- AUTH_CLIENT_ID = <App registration (audience)>
- AUTH_ALLOWED_ROLES = admin,user (optional)
- AUTH_ALLOWED_TENANTS = <comma-separated list> (future multi-tenant)
- AUTH_CLOCK_TOLERANCE_SECONDS = 5 (optional leeway)

## Quick Example
```ts
import { validateToken } from "./dist/token/validator.js";

const raw = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."; // a real bearer token
const validated = await validateToken(raw, {
  tenantId: process.env.AUTH_TENANT_ID!,
  clientId: process.env.AUTH_CLIENT_ID!,
  roleMapping: { allowed: ["admin","user"] }
});
console.log(validated.payload.sub, validated.payload.roles);
```

## Middleware Example (framework-agnostic style)
```ts
import { authMiddleware } from "./dist/token/middleware.js";

const mw = authMiddleware({
  tenantId: process.env.AUTH_TENANT_ID!,
  clientId: process.env.AUTH_CLIENT_ID!,
  roleMapping: { requiredAny: ["admin"] }
});

// Pseudocode integration:
server.use(async (req,res,next) => mw(req,res,next));
```

## Scripts
- `npm run check` → typecheck + lint + tests
- `npm run test:coverage` → coverage output (lcov/html in coverage/)
- `npm run build` → generate dist with declarations

## Conventions
- All public APIs are exported via `src/index.ts`
- Non-executable surfaces (examples) excluded from coverage
- Errors use structured classes (with stable `code`)

## License
MIT