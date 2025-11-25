# eva-auth

Enterprise authentication and authorization module for EVA 2.0 platform. Provides Microsoft Entra ID (Azure AD) JWT token validation, role-based access control (RBAC), and framework-agnostic middleware for securing APIs.

## 🎯 Features

- ✅ **Microsoft Entra ID Integration** - JWT token validation with JWKS key caching
- ✅ **Role-Based Access Control** - Flexible role mapping and permission checks
- ✅ **Tenant Isolation** - Cross-tenant boundary enforcement for multi-tenant scenarios
- ✅ **Framework Agnostic** - Works with Express, Fastify, and any HTTP framework
- ✅ **Security First** - Token expiration, audience/issuer validation, strict error handling
- ✅ **Type Safe** - Full TypeScript support with strict mode enabled
- ✅ **Test Coverage** - Comprehensive test suite with 77%+ coverage

## 📦 Installation

```bash
npm install eva-auth
```

## 🚀 Quick Start

### Basic Token Validation

```typescript
import { validateToken } from "eva-auth";

const validated = await validateToken(token, {
  tenantId: "your-tenant-id",
  clientId: "your-client-id",
});

console.log("User:", validated.payload.sub);
console.log("Roles:", validated.payload.roles);
```

### Express Middleware

```typescript
import { authMiddleware } from "eva-auth";

app.use(
  authMiddleware({
    tenantId: process.env.ENTRA_TENANT_ID!,
    clientId: process.env.ENTRA_CLIENT_ID!,
  }),
);
```

## 📚 API Reference

See full documentation in [docs/](./docs/) directory.

## 🔐 Security

- JWT signature verification with JWKS
- Audience and issuer validation
- Token expiration checks
- Tenant boundary enforcement
- Role-based access control

## 🧪 Testing

```bash
npm test              # Run tests
npm run test:coverage # With coverage
```

Current coverage: **77%+** (statements, branches, functions)

## 📄 License

MIT - Part of EVA 2.0 Platform
