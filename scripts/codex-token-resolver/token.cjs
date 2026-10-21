// Turnstile Codex token resolver for Windows.
// The MSAL cache is encrypted for the current user with Windows DPAPI.
const path = require('node:path');
const { PublicClientApplication } = require('@azure/msal-node');
const {
  DataProtectionScope,
  FilePersistenceWithDataProtection,
  PersistenceCachePlugin,
} = require('@azure/msal-node-extensions');

const requiredEnvironment = [
  'TURNSTILE_TENANT_ID',
  'TURNSTILE_CODEX_CLIENT_ID',
  'TURNSTILE_GATEWAY_AUDIENCE',
];
const missingEnvironment = requiredEnvironment.filter(name => !process.env[name]);
if (missingEnvironment.length > 0) {
  console.error(`Missing resolver configuration: ${missingEnvironment.join(', ')}`);
  process.exit(1);
}

const tenantId = process.env.TURNSTILE_TENANT_ID;
const clientId = process.env.TURNSTILE_CODEX_CLIENT_ID;
const audience = process.env.TURNSTILE_GATEWAY_AUDIENCE;
const scope = process.env.TURNSTILE_GATEWAY_SCOPE || `api://${audience}/Model.Invoke`;
const cachePath = process.env.TURNSTILE_CODEX_CACHE
  || path.join(process.env.USERPROFILE || process.env.HOME, '.codex', 'turnstile-auth', 'token-cache.bin');

async function main() {
  const persistence = await FilePersistenceWithDataProtection.create(
    cachePath,
    DataProtectionScope.CurrentUser,
    '',
  );
  const app = new PublicClientApplication({
    auth: { clientId, authority: `https://login.microsoftonline.com/${tenantId}` },
    cache: { cachePlugin: new PersistenceCachePlugin(persistence) },
  });
  const accounts = await app.getTokenCache().getAllAccounts();
  let result;
  if (process.argv.includes('--login')) {
    result = await app.acquireTokenByDeviceCode({
      scopes: [scope],
      deviceCodeCallback: ({ message }) => console.error(message),
    });
  } else {
    if (accounts.length !== 1) {
      throw new Error('Run the resolver with --login before requesting a token.');
    }
    result = await app.acquireTokenSilent({ account: accounts[0], scopes: [scope] });
  }
  if (!result?.accessToken) throw new Error('MSAL did not return an access token.');
  const claims = JSON.parse(Buffer.from(result.accessToken.split('.')[1], 'base64url').toString('utf8'));
  if (claims.tid !== tenantId
      || ![audience, `api://${audience}`].includes(claims.aud)
      || (claims.azp || claims.appid) !== clientId
      || !claims.scp?.split(' ').includes('Model.Invoke')) {
    throw new Error('Token claims do not match the configured Turnstile tenant, API, client, and scope.');
  }
  if (process.argv.includes('--check')) {
    console.log(JSON.stringify({
      aud: claims.aud,
      azp: claims.azp || claims.appid,
      scp: claims.scp,
      tid: claims.tid,
      expires: new Date(claims.exp * 1000).toISOString(),
    }));
  } else {
    // Codex provider.auth requires exactly the bearer token on stdout.
    process.stdout.write(`${result.accessToken}\n`);
  }
}

main().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
