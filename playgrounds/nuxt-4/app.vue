<!-- #region docs -->
<script setup lang="ts">
const log = ref<string[]>([]);
const say = (line: string) => log.value.unshift(line);

async function call(path: string, method: "GET" | "POST" = "GET", body?: Record<string, unknown>) {
  try {
    const result = await $fetch(path, { method, body });
    say(`${method} ${path} → ${JSON.stringify(result)}`);
  } catch (error) {
    const failure = error as { statusCode?: number; data?: { message?: string }; message?: string };
    say(
      `${method} ${path} → ${failure.statusCode ?? "?"} ${failure.data?.message ?? failure.message}`,
    );
  }
}

function openSocket() {
  const ws = new WebSocket(`${location.origin.replace("http", "ws")}/ws`);
  ws.addEventListener("open", () => ws.send("ping"));
  ws.addEventListener("message", (event) => say(`ws ← ${event.data}`));
  ws.addEventListener("error", () => say("ws → refused"));
  ws.addEventListener("close", (event) => say(`ws closed (${event.code})`));
}
</script>

<template>
  <main style="font-family: system-ui; max-width: 40rem; margin: 2rem auto">
    <h1>unjwt on Nuxt 4</h1>
    <p>
      <button @click="call('/login', 'POST', { user: 'user_1a2b' })">login</button>
      <button @click="call('/me')">me</button>
      <button @click="call('/logout', 'POST')">logout</button>
      <button @click="openSocket()">websocket</button>
      <button @click="call('/throw-after-clear')">throw after clear</button>
    </p>
    <pre v-for="(line, i) in log" :key="i">{{ line }}</pre>
  </main>
</template>
<!-- #endregion -->
