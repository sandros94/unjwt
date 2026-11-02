// #region token
import { HTTPError, readBody } from "h3";
import { isJWTError } from "unjwt/error";
import { app, appSession } from "./h3.ts";

app.get("/reports", (event) => {
  const token = appSession.token(event);
  if (!token) throw new HTTPError({ status: 401, message: "Sign in first" });
  // Passed on unopened: the reports service checks it with its own copy of the key
  return fetch("https://reports.example.com/v1/summary", {
    headers: { authorization: `Bearer ${token}` },
  });
});
// #endregion

// #region issue
app.post("/api-token", async (event) => {
  const session = await appSession.use(event);
  if (!session.id) throw new HTTPError({ status: 401, message: "Sign in first" });
  const token = await appSession.issue({ user: session.data.user }, { maxAge: "15m" });
  return { token };
});
// #endregion

// #region open
app.post("/internal/session-check", async (event) => {
  const body = await readBody<{ token?: unknown }>(event);
  if (typeof body?.token !== "string") return { valid: false };
  try {
    const { data, expiresAt } = await appSession.open(body.token);
    return { valid: true, user: data.user, expiresAt };
  } catch (error) {
    if (isJWTError(error)) return { valid: false };
    throw error;
  }
});
// #endregion

export { app };
