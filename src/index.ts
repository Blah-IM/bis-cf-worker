/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.toml`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

import { BlahPublicKey } from '@blah-im/core/crypto';
import { BlahIdentity, blahIdentityFileSchema } from '@blah-im/core/identity';

const IDENTITY_FILE_KEY_PREFIX = 'identity-file:';

function error(statusCode: number, type: string, details: unknown) {
	return new Response(JSON.stringify({ error: type, details }), { status: statusCode, headers: { 'content-type': 'application/json' } });
}

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const url = new URL(request.url);
		const idKeyId = url.hostname.match(/^([0-9a-f]+)\./gi)?.[0];

		if (!idKeyId) {
			if (url.pathname === '/') {
				return new Response('This is a Blah Identity server for testing.', { status: 200, headers: { 'content-type': 'text/plain' } });
			}
			if (request.method !== 'GET') {
				return new Response('Method Not Allowed', { status: 405 });
			}
		}

		if (url.pathname === '/.well-known/blah/identity.json') {
			switch (request.method) {
				case 'GET': {
					const identityFile = await env.KV.get(IDENTITY_FILE_KEY_PREFIX + idKeyId);
					if (identityFile) {
						return new Response(identityFile, { status: 200, headers: { 'content-type': 'application/json' } });
					}
					break;
				}
				case 'PUT': {
					const currentDate = new Date();
					const signedIdentityFile = await request.json();
					const { payload: identityFile, key: payloadSigningActKey } = await BlahPublicKey.parseAndVerifyPayload(
						blahIdentityFileSchema,
						signedIdentityFile
					);
					const identity = await BlahIdentity.fromIdentityFile(identityFile);

					let isPayloadSigningActKeyValid = false;
					for (const actKey of identity.actKeys) {
						if (!actKey.sigValid) return error(403, 'act_key_sig_invalid', { act_key: actKey.publicKey.id });
						if (actKey.publicKey.id === payloadSigningActKey.id) {
							if (actKey.expiresAt < currentDate)
								return error(403, 'signing_act_key_expired', {
									act_key: actKey.publicKey.id,
									act_key_expires_at: actKey.expiresAt.getTime(),
									current_date: currentDate.getTime(),
								});
							isPayloadSigningActKeyValid = true;
						}
					}
					if (!isPayloadSigningActKeyValid) return error(403, 'signing_key_is_not_act_key', { signing_key: payloadSigningActKey.id });
					if (!identity.profileSigValid) return error(403, 'profile_sig_invalid', undefined);
					if (identity.idPublicKey.id !== idKeyId)
						return error(403, 'identity_key_id_domain_mismatch', { identity_file_id_key_id: identity.idPublicKey.id, subdomain: idKeyId });

					await env.KV.put(IDENTITY_FILE_KEY_PREFIX + idKeyId, JSON.stringify(signedIdentityFile), { expirationTtl: 60 * 60 * 24 * 365 });
					break;
				}
			}
		}

		return new Response('Not Found', { status: 404 });
	},
} satisfies ExportedHandler<Env>;
