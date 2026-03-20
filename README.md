# @xferops/auth-middleware (DEPRECATED)

Shared JWT validation middleware for XferOps apps.

## Installation

```bash
npm install @xferops/auth-middleware
```

## Usage

```typescript
import { validateJWT, createJWT } from '@xferops/auth-middleware';

const secret = process.env.AUTH_SECRET!;

// Validate a token
const result = await validateJWT(token, secret);
if (result.valid) {
  console.log('User:', result.payload?.userId);
}

// Create a token
const token = await createJWT({ userId: '123', email: 'user@example.com' }, secret);
```

## Development

```bash
npm install
npm test
npm run build
```
