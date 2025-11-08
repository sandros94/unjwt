# H3 Session Adapters - Usage Guide

This document provides comprehensive guidance on how to properly use the H3 session adapter functions for JWT-based session management in H3 applications.

## Table of Contents

1. [H3 v1 vs v2 Adapters](#h3-v1-vs-v2-adapters)
2. [What These Adapters Handle](#what-these-adapters-handle)
3. [Type System Overview](#type-system-overview)
4. [JWE vs JWS: When to Use Which](#jwe-vs-jws-when-to-use-which)
5. [Simple Usage (Recommended)](#simple-usage-recommended)
6. [Advanced Usage](#advanced-usage)

---

## H3 v1 vs v2 Adapters

Both `unjwt/adapters/h3v1` and `unjwt/adapters/h3v2` are available and provide identical APIs for session management. **For general use, import from `unjwt/adapters/h3`** which currently aliases to `h3v1` but will default to `h3v2` in a future breaking change (once Nuxt v5 and Nitro v3 reach stable releases).

### Key Differences

The adapters are API-compatible, with only one developer-facing difference:

#### Cookie Chunking (h3v2 only)

**h3v2** includes built-in support for automatic cookie chunking for large session tokens:

```typescript
// h3v2 supports chunkMaxLength in cookie config
import { useJWESession } from "unjwt/adapters/h3v2";

const session = await useJWESession(event, {
  key: process.env.SESSION_SECRET!,
  cookie: {
    chunkMaxLength: 512, // Automatically split cookies larger than 512 bytes
  },
});
```

**h3v1** does not have built-in chunking support - large tokens may exceed browser cookie size limits (typically 4KB).

### Which Adapter to Use?

- **Use `unjwt/adapters/h3`**: Recommended for maximum compatibility and future-proofing
- **Use `unjwt/adapters/h3v2`**: If you specifically need cookie chunking or are using h3 v2.x
- **Use `unjwt/adapters/h3v1`**: Only if you must pin to h3 v1.x

All examples in this document use `unjwt/adapters/h3` and work with both versions.

---

## What These Adapters Handle

These session adapters are **high-level utilities** that handle the complete session lifecycle. When using these adapters, you do NOT need to:

### ❌ Things You Should NOT Do

- **DO NOT** manually populate `event.context.sessions`
- **DO NOT** manually update `event.context.sessions`
- **DO NOT** manually read cookies or headers for session tokens
- **DO NOT** manually call `setCookie()` for sessions
- **DO NOT** manually encrypt/decrypt or sign/verify session tokens
- **DO NOT** manually validate JWT claims (exp, iat, jti)
- **DO NOT** manually generate session IDs
- **DO NOT** manually calculate expiration times

### ✅ Things These Adapters Handle Automatically

- **Token Storage**: Automatically reads from and writes to cookies and/or custom headers
- **Context Management**: Manages `event.context.sessions[sessionName]` internally
- **Session Lifecycle**: Initialization, updates, expiration checks, and cleanup
- **Token Operations**: Encryption/decryption (JWE) or signing/verification (JWS)
- **Claim Management**: Automatically handles `jti`, `iat`, `exp` JWT claims
- **Expiration Logic**: Validates token expiration and triggers appropriate hooks
- **ID Generation**: Uses `crypto.randomUUID()` by default
- **Cookie Configuration**: Sets secure, httpOnly defaults for cookies
- **Error Handling**: Provides hooks for errors, expiration, and lifecycle events

---

## Type System Overview

### Core Types

```typescript
// SessionData - Your application's session data
// Automatically excludes reserved JWT claims (jti, iat, exp)
type SessionData<T extends JWTClaims = JWTClaims> = Omit<
  T,
  "jti" | "iat" | "exp"
>;

// SessionUpdate - How to update session data
type SessionUpdate<T extends JWTClaims = JWTClaims> =
  | Partial<SessionData<T>> // Direct partial update
  | ((oldData: SessionData<T>) => Partial<SessionData<T>> | undefined); // Function update

// SessionManager - The main interface you interact with
interface SessionManager<T extends JWTClaims = JWTClaims> {
  readonly id: string | undefined; // Session identifier (from jti)
  readonly createdAt: number; // Session creation timestamp in ms (from iat)
  readonly expiresAt: number | undefined; // Expiration timestamp in ms (from exp)
  readonly data: SessionData<T>; // Your application data
  update: (update: SessionUpdate<T>) => Promise<SessionManager<T>>;
  clear: () => Promise<SessionManager<T>>;
}
```

### Configuration Types

Both JWE and JWS adapters share similar configuration patterns:

```typescript
interface SessionConfigJWE<T extends JWTClaims = JWTClaims> {
  key: string | JWK_Symmetric | JWK_Private | { privateKey: JWK_Private | JWK_Symmetric; publicKey?: JWK_Public };
  maxAge?: ExpiresIn;                        // Session lifetime in seconds (or string representation: "1h", "7D", "2weeks", etc.)
  name?: string;                             // Cookie/header name (default: "h3-jwe" or "h3-jws")
  cookie?: false | CookieSerializeOptions;   // Cookie options or false to disable
  sessionHeader?: false | string;            // Custom header name or false to disable
  generateId?: () => string;                 // Custom ID generator
  jwe?: { encryptOptions?: ..., decryptOptions?: ... };
  hooks?: SessionHooksJWE<T>;
}

interface SessionConfigJWS<T extends JWTClaims = JWTClaims> {
  key: JWK_Symmetric | { privateKey: JWK_Private; publicKey: JWK_Public | JWK_Public[] | JWKSet };
  maxAge?: ExpiresIn;
  name?: string;
  cookie?: false | CookieSerializeOptions;
  sessionHeader?: false | string;
  generateId?: () => string;
  jws?: { signOptions?: ..., verifyOptions?: ... };
  hooks?: SessionHooksJWS<T>;
}
```

### Session Hooks

Both adapters support lifecycle hooks:

```typescript
interface SessionHooks<T extends JWTClaims = JWTClaims> {
  onRead?: (args: {
    session: Session<T>;
    event: H3Event;
    config: SessionConfig<T>;
  }) => void | Promise<void>;
  onUpdate?: (args: {
    session: Session<T>;
    event: H3Event;
    config: SessionConfig<T>;
  }) => void | Promise<void>;
  onClear?: (args: {
    event: H3Event;
    config: Partial<SessionConfig<T>>;
  }) => void | Promise<void>;
  onExpire?: (args: {
    event: H3Event;
    error: Error;
    config: SessionConfig<T>;
  }) => void | Promise<void>;
  onError?: (args: {
    event: H3Event;
    error: any;
    config: SessionConfig<T>;
  }) => void | Promise<void>;
}
```

---

## JWE vs JWS: When to Use Which

### JWE (JSON Web Encryption) - **Recommended for Most Cases**

**Use JWE when:**

- Session data contains sensitive information (user details, permissions, etc.)
- You need privacy and confidentiality
- Session data should NOT be readable by clients
- You want both encryption AND integrity protection

**Key Features:**

- Data is encrypted (not visible to clients)
- Can use symmetric keys (passwords/oct JWKs) or asymmetric keys
- Slightly larger token size due to encryption overhead
- Default cookie: `httpOnly: true, secure: true`

### JWS (JSON Web Signature) - **Use with Caution**

**Use JWS when:**

- Session data is NOT sensitive (e.g., theme preference, language)
- You only need integrity protection, not confidentiality
- Clients need to read session data client-side
- You need smaller token sizes

**⚠️ WARNING:**

- JWS tokens are **NOT encrypted** - data is only Base64URL-encoded
- Anyone can decode and read the payload
- Only signature prevents tampering
- Default cookie: `httpOnly: false, secure: true` (readable by client JS)

**Example of JWS payload visibility:**

```javascript
// A JWS token can be decoded client-side:
const parts = jwsToken.split(".");
const payload = JSON.parse(atob(parts[1])); // Reveals all session data!
```

---

## Simple Usage (Recommended)

For 95% of use cases, you only need `useJWESession()` or `useJWSSession()`. These functions handle everything automatically.

### Basic JWE Session (Encrypted, Recommended)

```typescript
import { defineEventHandler } from "h3";
import { type JWTClaims, useJWESession } from "unjwt/adapters/h3";

// Define your session data type
interface MySessionData extends JWTClaims {
  userId: string;
  username: string;
  roles: string[];
}

export default defineEventHandler(async (event) => {
  // Initialize session with a symmetric key (password-based encryption)
  const session = await useJWESession<MySessionData>(event, {
    key: process.env.SESSION_SECRET!, // String for PBES2
    maxAge: 60 * 60 * 24 * 7, // 7 days in seconds
  });

  // Read session data
  console.log("Session ID:", session.id);
  console.log("User ID:", session.data.userId);
  console.log("Expires at:", new Date(session.expiresAt));

  // Update session data (automatically re-encrypts and updates cookie)
  await session.update({
    username: "new-username",
    roles: ["admin", "user"],
  });

  // Or update using a function
  await session.update((oldData) => ({
    roles: [...oldData.roles, "moderator"],
  }));

  // Clear session (deletes from context and expires cookie)
  await session.clear();

  return { success: true };
});
```

### Basic JWS Session (Signed, Not Encrypted)

```typescript
import { defineEventHandler } from "h3";
import { type JWTClaims, useJWSSession, generateJWK } from "unjwt/adapters/h3";

// Non-sensitive session data only!
interface PublicSessionData extends JWTClaims {
  theme: "light" | "dark";
  language: string;
  userId: string; // ID is OK, but no sensitive details
}

export default defineEventHandler(async (event) => {
  // For JWS, you need a JWK (not a password string)
  const { privateKey, publicKey } = await generateJWK("ES256");

  const session = await useJWSSession<PublicSessionData>(event, {
    key: { privateKey, publicKey },
    maxAge: 60 * 60 * 24, // 1 day
  });

  // Read and update session
  console.log("Theme:", session.data.theme);

  await session.update({ theme: "dark" });

  return { theme: session.data.theme };
});
```

### Using Hooks for Logging and Validation

```typescript
import { useJWESession } from "unjwt/adapters/h3";

export default defineEventHandler(async (event) => {
  const session = await useJWESession(event, {
    key: process.env.SESSION_SECRET!,
    maxAge: 3600,
    hooks: {
      // Called after session is read
      onRead: async ({ session, event }) => {
        console.log(`Session ${session.id} accessed by ${event.node.req.url}`);
      },

      // Called after session is updated
      onUpdate: async ({ session, event }) => {
        console.log(`Session ${session.id} updated:`, session.data);
      },

      // Called when session is cleared
      onClear: async ({ event }) => {
        console.log("Session cleared");
      },

      // Called when session expires
      onExpire: async ({ event, error }) => {
        console.warn("Session expired:", error.message);
        // You could redirect to login here
      },

      // Called on any error (invalid token, decryption failure, etc.)
      onError: async ({ event, error }) => {
        console.error("Session error:", error);
      },
    },
  });

  return { userId: session.data.userId };
});
```

### Custom Cookie Configuration

```typescript
import { useJWESession } from "unjwt/adapters/h3";

export default defineEventHandler(async (event) => {
  const session = await useJWESession(event, {
    key: process.env.SESSION_SECRET!,
    name: "my-app-session", // Custom cookie name
    maxAge: 3600,
    cookie: {
      path: "/api",
      secure: true,
      httpOnly: true,
      sameSite: "strict",
      domain: ".example.com", // Share across subdomains
    },
  });

  return { success: true };
});
```

### Using Custom Headers

#### Read from Authorization Header (fallback to cookie)

```typescript
import { useJWESession } from "unjwt/adapters/h3";

export default defineEventHandler(async (event) => {
  const session = await useJWESession(event, {
    key: process.env.SESSION_SECRET!,
    maxAge: 3600,
    sessionHeader: "Authorization", // It will try to read from this header first then cookie
  });

  // Client must send: Authorization: Bearer <jwt-token>

  return { userId: session.data.userId };
});
```

#### Read from Custom Header Only

```typescript
import { useJWESession } from "unjwt/adapters/h3";

export default defineEventHandler(async (event) => {
  const session = await useJWESession(event, {
    key: process.env.SESSION_SECRET!,
    maxAge: 3600,
    cookie: false, // Disable cookies entirely
    sessionHeader: "X-API-Session", // Read from this header
  });

  // Client must send: X-API-Session: <jwt-token>
  // or: X-API-Session: Bearer <jwt-token>

  return { userId: session.data.userId };
});
```

### TypeScript: Strongly Typed Sessions

```typescript
import { type JWTClaims, useJWESession } from "unjwt/adapters/h3";

interface UserSession extends JWTClaims {
  userId: string;
  email: string;
  roles: string[];
  preferences: {
    theme: string;
    notifications: boolean;
  };
}

export default defineEventHandler(async (event) => {
  // TypeScript now knows the exact shape of session.data
  const session = await useJWESession<UserSession>(event, {
    key: process.env.SESSION_SECRET!,
    maxAge: 3600,
  });

  // ✅ Type-safe access
  const userId: string = session.data.userId;
  const theme: string = session.data.preferences.theme;

  // ✅ Type-safe updates
  await session.update({
    preferences: {
      theme: "dark",
      notifications: true,
    },
  });

  // ❌ TypeScript error - invalid property
  // await session.update({ invalidProp: true });

  return { userId, theme };
});
```

### Conditional Session Updates

```typescript
import { useJWESession } from "unjwt/adapters/h3";

export default defineEventHandler(async (event) => {
  const session = await useJWESession(event, {
    key: process.env.SESSION_SECRET!,
    maxAge: 3600,
  });

  // Only update if condition is met
  await session.update((oldData) => {
    if (oldData.loginCount < 5) {
      return { loginCount: oldData.loginCount + 1 };
    }
    // Return undefined to skip update
    return undefined;
  });

  return { success: true };
});
```

---

## Advanced Usage

For advanced scenarios where you need fine-grained control over the session lifecycle, you can use the lower-level functions directly.

### Advanced Use Cases

When to use advanced functions:

- Custom token storage (e.g., database, Redis)
- Server-to-server token passing
- WebSocket authentication
- Custom token generation/validation logic
- Read-only session access (e.g., WebSocket upgrade events)

### JWE Advanced Functions

#### `getJWESession()` - Read or Initialize Session

Use when you need to read a session without immediately updating it.

```typescript
import { getJWESession } from "unjwt/adapters/h3";

export default defineEventHandler(async (event) => {
  const config = {
    key: process.env.SESSION_SECRET!,
    maxAge: 3600,
  };

  // Get existing session or create new one
  const session = await getJWESession(event, config);

  // Session is stored in event.context.sessions['h3-jwe']
  console.log("Session ID:", session.id);
  console.log("Session data:", session.data);
  console.log("Created at:", new Date(session.createdAt));
  console.log("Expires at:", new Date(session.expiresAt));

  return { session };
});
```

#### `updateJWESession()` - Update and Re-encrypt

Use when you want to update session data and automatically re-issue the encrypted token.

```typescript
import { getJWESession, updateJWESession } from "unjwt/adapters/h3";

export default defineEventHandler(async (event) => {
  const config = {
    key: process.env.SESSION_SECRET!,
    maxAge: 3600,
  };

  // Get current session
  await getJWESession(event, config);

  // Update with partial data
  await updateJWESession(event, config, {
    username: "new-username",
  });

  // Update with function
  await updateJWESession(event, config, (oldData) => ({
    loginCount: (oldData.loginCount || 0) + 1,
    lastLogin: Date.now(),
  }));

  // Update without data change (just re-issue token)
  await updateJWESession(event, config);

  return { success: true };
});
```

#### `sealJWESession()` - Generate Encrypted Token

Use when you need to manually create a JWE token (e.g., for server-to-server communication).

```typescript
import { getJWESession, sealJWESession } from "unjwt/adapters/h3";

export default defineEventHandler(async (event) => {
  const config = {
    key: process.env.SESSION_SECRET!,
    maxAge: 3600,
  };

  // Initialize session
  await getJWESession(event, config);

  // Get encrypted token string
  const token = await sealJWESession(event, config);

  // Token structure:
  // {
  //   jti: "session-id",
  //   iat: 1234567890,  // seconds
  //   exp: 1234571490,  // seconds
  //   ...session.data   // Your custom data
  // }

  // Use token for custom purposes
  return {
    token,
    // E.g., send to another service, store in database, etc.
  };
});
```

#### `unsealJWESession()` - Decrypt Token Manually

Use when you need to verify and decrypt a JWE token from external sources.

```typescript
import { unsealJWESession } from "unjwt/adapters/h3";

export default defineEventHandler(async (event) => {
  const config = {
    key: process.env.SESSION_SECRET!,
    maxAge: 3600,
  };

  // Get token from custom source (e.g., query param, database)
  const tokenFromQuery = event.node.req.url?.split("token=")[1];

  if (tokenFromQuery) {
    try {
      const sessionData = await unsealJWESession(event, config, tokenFromQuery);

      console.log("Decrypted session:", sessionData);
      // {
      //   id: "session-id",
      //   createdAt: 1234567890000,  // milliseconds
      //   expiresAt: 1234571490000,  // milliseconds
      //   data: { ...yourData }
      // }

      return { valid: true, session: sessionData };
    } catch (error) {
      // Token invalid, expired, or tampered
      return { valid: false, error: error.message };
    }
  }

  return { valid: false };
});
```

#### `clearJWESession()` - Manually Clear Session

Use when you need to clear a session in custom scenarios.

```typescript
import { clearJWESession } from "unjwt/adapters/h3";

export default defineEventHandler(async (event) => {
  const config = {
    key: process.env.SESSION_SECRET!,
    name: "my-session",
  };

  // Clear session (removes from context and expires cookie)
  await clearJWESession(event, config);

  return { loggedOut: true };
});
```

### JWS Advanced Functions

JWS functions mirror JWE functions but use signing instead of encryption.

#### `getJWSSession()` - Read or Initialize Session

```typescript
import { getJWSSession, generateJWK } from "unjwt/adapters/h3";

export default defineEventHandler(async (event) => {
  const { privateKey, publicKey } = await generateJWK("ES256");

  const config = {
    key: { privateKey, publicKey },
    maxAge: 3600,
  };

  const session = await getJWSSession(event, config);

  return { session };
});
```

#### `updateJWSSession()` - Update and Re-sign

```typescript
import {
  getJWSSession,
  updateJWSSession,
  generateJWK,
} from "unjwt/adapters/h3";

export default defineEventHandler(async (event) => {
  const { privateKey, publicKey } = await generateJWK("ES256");

  const config = {
    key: { privateKey, publicKey },
    maxAge: 3600,
  };

  await getJWSSession(event, config);

  // Update session data
  await updateJWSSession(event, config, {
    theme: "dark",
  });

  return { success: true };
});
```

#### `signJWSSession()` - Generate Signed Token

```typescript
import { getJWSSession, signJWSSession, generateJWK } from "unjwt/adapters/h3";

export default defineEventHandler(async (event) => {
  const { privateKey, publicKey } = await generateJWK("ES256");

  const config = {
    key: { privateKey, publicKey },
    maxAge: 3600,
  };

  await getJWSSession(event, config);

  // Get signed token
  const token = await signJWSSession(event, config);

  // ⚠️ Remember: JWS tokens are NOT encrypted!
  // Payload is visible to anyone who decodes the token

  return { token };
});
```

#### `verifyJWSSession()` - Verify Token Manually

```typescript
import { verifyJWSSession, generateJWK } from "unjwt/adapters/h3";

export default defineEventHandler(async (event) => {
  const { privateKey, publicKey } = await generateJWK("ES256");

  const config = {
    key: { privateKey, publicKey },
    maxAge: 3600,
  };

  const tokenFromHeader = event.node.req.headers["x-custom-token"];

  if (tokenFromHeader) {
    try {
      const sessionData = await verifyJWSSession(
        event,
        config,
        String(tokenFromHeader),
      );

      return { valid: true, session: sessionData };
    } catch (error) {
      return { valid: false, error: error.message };
    }
  }

  return { valid: false };
});
```

#### `clearJWSSession()` - Manually Clear Session

```typescript
import { clearJWSSession, generateJWK } from "unjwt/adapters/h3";

export default defineEventHandler(async (event) => {
  const { privateKey, publicKey } = await generateJWK("ES256");

  const config = {
    key: { privateKey, publicKey },
  };

  await clearJWSSession(event, config);

  return { loggedOut: true };
});
```

### Advanced Pattern: Custom Token Storage

Store tokens in Redis instead of cookies:

```typescript
import {
  getJWESession,
  sealJWESession,
  unsealJWESession,
} from "unjwt/adapters/h3";
import { redis } from "./redis-client";

export default defineEventHandler(async (event) => {
  const config = {
    key: process.env.SESSION_SECRET!,
    maxAge: 3600,
    cookie: false, // Disable automatic cookie handling
    sessionHeader: false, // Disable automatic header reading
  };

  const sessionId = event.node.req.headers["x-session-id"];

  if (sessionId) {
    // Load token from Redis
    const token = await redis.get(`session:${sessionId}`);

    if (token) {
      try {
        // Manually unseal and populate context
        const sessionData = await unsealJWESession(event, config, token);

        // Manually populate event.context.sessions
        if (!event.context.sessions) {
          event.context.sessions = {};
        }
        event.context.sessions["h3-jwe"] = {
          ...sessionData,
          data: sessionData.data || {},
        };
      } catch (error) {
        // Invalid/expired token
        await redis.del(`session:${sessionId}`);
      }
    }
  }

  // Get or create session
  const session = await getJWESession(event, config);

  // Store updated token in Redis
  const token = await sealJWESession(event, config);
  await redis.set(`session:${session.id}`, token, "EX", 3600);

  return {
    sessionId: session.id,
    data: session.data,
  };
});
```

### Advanced Pattern: WebSocket Authentication

Authenticate WebSocket connections using session tokens:

```typescript
import { defineWebSocketHandler } from "h3";
import { unsealJWESession } from "unjwt/adapters/h3";

export default defineWebSocketHandler({
  async upgrade(event) {
    const config = {
      key: process.env.SESSION_SECRET!,
      maxAge: 3600,
    };

    // Get token from query param or header
    const url = new URL(event.node.req.url!, "http://localhost");
    const token = url.searchParams.get("token");

    if (!token) {
      return { statusCode: 401, statusMessage: "Unauthorized" };
    }

    try {
      // Verify token before upgrading
      const sessionData = await unsealJWESession(event, config, token);

      // Store user info for WebSocket handler
      event.context.user = sessionData.data;

      return { statusCode: 101 }; // Proceed with upgrade
    } catch (error) {
      return { statusCode: 401, statusMessage: "Invalid token" };
    }
  },

  async message(peer, message) {
    // Access authenticated user
    console.log("Message from user:", peer.ctx.user.userId);
  },
});
```

### Advanced Pattern: Server-to-Server Authentication

Share session tokens between microservices:

```typescript
// Service A: Create token
import { getJWESession, sealJWESession } from "unjwt/adapters/h3";

export default defineEventHandler(async (event) => {
  const config = {
    key: process.env.SHARED_SECRET!, // Same secret across services
    maxAge: 300, // Short-lived for service-to-service
  };

  const session = await getJWESession(event, config);
  session.data.serviceRole = "api-gateway";

  const token = await sealJWESession(event, config);

  // Send token to Service B
  const response = await fetch("https://service-b/api/data", {
    headers: {
      Authorization: token,
    },
  });

  return response.json();
});

// Service B: Verify token
import { unsealJWESession } from "unjwt/adapters/h3";

export default defineEventHandler(async (event) => {
  const config = {
    key: process.env.SHARED_SECRET!, // Same secret as Service A
    maxAge: 300,
  };

  const token = event.node.req.headers["x-service-token"];

  if (!token) {
    throw createError({ statusCode: 401, message: "Missing service token" });
  }

  try {
    const sessionData = await unsealJWESession(event, config, String(token));

    // Verify service role
    if (sessionData.data.serviceRole !== "api-gateway") {
      throw createError({ statusCode: 403, message: "Invalid service role" });
    }

    return { data: "Sensitive service data" };
  } catch (error) {
    throw createError({ statusCode: 401, message: "Invalid service token" });
  }
});
```

### Advanced Pattern: Read-Only Sessions

For contexts where you can't modify the session (e.g., WebSocket upgrade events):

```typescript
import { getJWESession } from "unjwt/adapters/h3";

export default defineEventHandler(async (event) => {
  const config = {
    key: process.env.SESSION_SECRET!,
    maxAge: 3600,
  };

  // getJWESession works with read-only events
  // It will read from cookie/header but won't try to update
  const session = await getJWESession(event, config);

  // ✅ Reading is safe
  console.log("User ID:", session.data.userId);

  // ❌ This would throw an error on read-only events
  // await updateJWESession(event, config, { ... });

  return { userId: session.data.userId };
});
```

---

## Best Practices

### 1. Default to Simple Usage

**Always prefer** `useJWESession()` or `useJWSSession()` unless advanced control is needed.

```typescript
// ✅ Good - Simple and handles everything
const session = await useJWESession(event, config);
await session.update({ userId: "123" });

// ❌ Avoid unless necessary
const session = await getJWESession(event, config);
await updateJWESession(event, config, { userId: "123" });
```

### 2. Choose JWE by Default

For single use, or when in doubt, use JWE for security:

```typescript
// ✅ Default choice - encrypted
import { useJWESession } from "unjwt/adapters/h3";

// ⚠️ Only use JWS when you need readable tokens
import { useJWSSession } from "unjwt/adapters/h3";
```

### 3. Never Manually Manage event.context.sessions

The adapters handle this automatically:

```typescript
// ❌ NEVER DO THIS
event.context.sessions = {
  "h3-jwe": { id: "123", data: {} },
};

// ✅ Let the adapter handle it
await useJWESession(event, config);
```

### 4. Use Hooks for Side Effects

Don't try to manually track session lifecycle:

```typescript
// ❌ Bad - manual tracking
const session = await useJWESession(event, config);
await logSessionAccess(session.id);
await session.update(data);
await logSessionUpdate(session.id);

// ✅ Good - use hooks
const session = await useJWESession(event, {
  key: process.env.SESSION_SECRET!,
  hooks: {
    onRead: async ({ session }) => logSessionAccess(session.id),
    onUpdate: async ({ session }) => logSessionUpdate(session.id),
  },
});
await session.update(data);
```

### 5. Type Your Sessions

Always use TypeScript generics for type safety:

```typescript
// ✅ Type-safe
interface MySession extends JWTClaims {
  userId: string;
  roles: string[];
}

const session = await useJWESession<MySession>(event, config);
const userId: string = session.data.userId; // Type-safe

// ❌ Untyped
const session = await useJWESession(event, config);
const userId = session.data.userId; // any type
```

### 6. Handle Expiration Gracefully

Use the `onExpire` hook for expired sessions:

```typescript
const session = await useJWESession(event, {
  key: process.env.SESSION_SECRET!,
  maxAge: 3600,
  hooks: {
    onExpire: async ({ event, error }) => {
      // Redirect to login, send 401, etc.
      throw createError({
        statusCode: 401,
        message: "Session expired, please login again",
      });
    },
  },
});
```

---

## Common Mistakes to Avoid

### ❌ Mistake 1: Manually Setting Cookies

```typescript
// ❌ WRONG - Don't manually set session cookies
setCookie(event, "session", token);

// ✅ RIGHT - Let the adapter handle it
await session.update(data); // Automatically updates cookie
```

### ❌ Mistake 2: Using JWS for Sensitive Data

```typescript
// ❌ WRONG - JWS exposes data to clients
const session = await useJWSSession(event, config);
await session.update({
  creditCardNumber: "1234-5678-9012-3456", // ⚠️ Visible to client!
});

// ✅ RIGHT - Use JWE for sensitive data
const session = await useJWESession(event, config);
await session.update({
  creditCardNumber: "1234-5678-9012-3456", // ✅ Encrypted
});
```

### ❌ Mistake 3: Mixing Simple and Advanced APIs

```typescript
// ❌ WRONG - Inconsistent usage
const session = await useJWESession(event, config);
await updateJWESession(event, config, data); // Why?

// ✅ RIGHT - Stick to one pattern
const session = await useJWESession(event, config);
await session.update(data);
```

### ❌ Mistake 4: Not Handling Update Errors

```typescript
// ❌ WRONG - Ignoring async errors
session.update(data); // Missing await

// ✅ RIGHT - Always await
await session.update(data);
```

### ❌ Mistake 5: Modifying Reserved Claims

```typescript
// ❌ WRONG - Reserved claims are managed automatically
await session.update({
  jti: "new-id", // ❌ Ignored
  iat: Date.now(), // ❌ Ignored
  exp: Date.now(), // ❌ Ignored
});

// ✅ RIGHT - Only update your data
await session.update({
  userId: "123", // ✅ Your data
  username: "john", // ✅ Your data
});
```

---

## Summary

- **Simple usage**: Use `useJWESession()` or `useJWSSession()` for 95% of cases
- **Default to JWE**: Unless you explicitly need readable tokens
- **Let adapters manage**: Don't manually handle cookies, context, or tokens
- **Use hooks**: For lifecycle events and side effects
- **Type your sessions**: Use TypeScript generics for safety
- **Advanced functions**: Only use when you need custom token handling

These adapters handle all the complexity of JWT session management. Trust them to do their job, and focus on your application logic.
