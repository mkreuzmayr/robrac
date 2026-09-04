import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { it } from 'node:test';

it('imports the browser client without loading Better Auth server APIs', () => {
  const clientURL = new URL('../src/client.ts', import.meta.url).href;
  const output = execFileSync(
    process.execPath,
    [
      '--input-type=module',
      '--eval',
      `
    import { registerHooks } from 'node:module';
    registerHooks({
      resolve(specifier, context, nextResolve) {
        if (specifier === 'better-auth/api') {
          throw new Error('The browser client imported Better Auth server APIs');
        }
        return nextResolve(specifier, context);
      },
    });
    const { robracClient, ROBRAC_PLUGIN_ID } = await import(${JSON.stringify(clientURL)});
    if (ROBRAC_PLUGIN_ID !== 'robrac' || typeof robracClient !== 'function') {
      throw new Error('Missing client exports');
    }
    if (robracClient().id !== 'infer-server-plugin') throw new Error('Invalid client plugin');
    console.log('client ok');
  `,
    ],
    { encoding: 'utf8' }
  );
  assert.match(output, /client ok/);
});
