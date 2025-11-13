import { validateToken } from "../token/validator.js";

async function main() {
  const raw = process.argv[2];
  if (!raw) {
    console.error("Usage: node dist/examples/validate.js <JWT>");
    return;
  }
  try {
    const result = await validateToken(raw, {
      tenantId: process.env.AUTH_TENANT_ID || "TENANT_GUID",
      clientId: process.env.AUTH_CLIENT_ID || "APP_CLIENT_ID"
    });
    console.log("Valid token for subject:", result.payload.sub);
    console.log("Roles:", result.payload.roles);
  } catch (e: any) {
    console.error("Validation failed:", e.message);
  }
}

void main();