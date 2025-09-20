import { Elysia, t, type Static } from 'elysia'
import { jwt } from '../src'
import { SignJWT } from 'jose'

import { describe, expect, it } from 'bun:test'

const post = (path: string, body = {}) =>
	new Request(`http://localhost${path}`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify(body)
	})

const TEST_SECRET = 'A'

describe('JWT Plugin', () => {
	const app = new Elysia()
		.use(
			jwt({
				name: 'jwt',
				secret: TEST_SECRET
				//exp: '1h' // default expiration,
				//iat: true - default iat included
			})
		)
		.post(
			'/sign-token',
			({ jwt, body }) =>
				jwt.sign({
					name: body.name,
					exp: '30m'
				}),
			{
				body: t.Object({
					name: t.String()
				})
			}
		)
		.post(
			'/sign-token-disable-exp-and-iat',
			({ jwt, body }) =>
				jwt.sign({
					name: body.name,
					// nbf: undefined,
					exp: undefined,
					iat: false,
				}),
			{
				body: t.Object({
					name: t.String()
				})
			}
		)
		.post(
			'/verify-token',
			async ({ jwt, body }) => {
				const verifiedPayload = await jwt.verify(body.token)
				if (!verifiedPayload) {
					return {
						success: false,
						data: null,
						message: 'Verification failed'
					}
				}
				return { success: true, data: verifiedPayload }
			},
			{
				body: t.Object({ token: t.String() })
			}
		)
		.post(
			'/verify-token-with-exp-and-iat',
			async ({ jwt, body }) => {
				const verifiedPayload = await jwt.verify(body.token)
				if (!verifiedPayload) {
					return {
						success: false,
						data: null,
						message: 'Verification failed'
					}
				}

				if (!verifiedPayload.exp) {
					return {
						success: false,
						data: null,
						message: 'exp was not setted on jwt'
					}
				}
				if (!verifiedPayload.iat) {
					return {
						success: false,
						data: null,
						message: 'iat was not setted on jwt'
					}
				}
				return { success: true, data: verifiedPayload }
			},
			{
				body: t.Object({ token: t.String() })
			}
		)

	it('should sign JWT and then verify', async () => {
		const payloadToSign = { name: 'Shirakami' }

		const signRequest = post('/sign-token', payloadToSign)
		const signResponse = await app.handle(signRequest)
		const token = await signResponse.text()

		expect(token.split('.').length).toBe(3)

		const verifyRequest = post('/verify-token', { token })
		const verifyResponse = await app.handle(verifyRequest)
		const verifiedResult = (await verifyResponse.json()) as {
			success: boolean
			data: { name: string; exp: number } | null
		}

		expect(verifiedResult.success).toBe(true)
		expect(verifiedResult.data?.name).toBe(payloadToSign.name)
		expect(verifiedResult.data?.exp).toBeDefined()
	})

	it('should return verification failed for an invalid token', async () => {
		const verifyRequest = post('/verify-token', {
			token: 'invalid'
		})
		const verifyResponse = await app.handle(verifyRequest)
		const verifiedResult = await verifyResponse.json()

		expect(verifiedResult.success).toBe(false)
		expect(verifiedResult.message).toBe('Verification failed')
	})

	it('should return verification failed for an expired token', async () => {
		const key = new TextEncoder().encode(TEST_SECRET)
		const expiredToken = await new SignJWT({ name: 'Expired User' })
			.setProtectedHeader({ alg: 'HS256' })
			.setExpirationTime(Math.floor(Date.now() / 1000) - 3600)
			.sign(key)

		const verifyRequest = post('/verify-token', { token: expiredToken })
		const verifyResponse = await app.handle(verifyRequest)
		const verifiedResult = await verifyResponse.json()

		expect(verifiedResult.success).toBe(false)
		expect(verifiedResult.message).toBe('Verification failed')
	})

	it('should sign JWT with default values (exp and iat) and then verify', async () => {
		const payloadToSign = { name: 'John Doe' }

		const signRequest = post('/sign-token', payloadToSign)
		const signResponse = await app.handle(signRequest)
		const token = await signResponse.text()

		expect(token.split('.').length).toBe(3)

		const verifyRequest = post('/verify-token-with-exp-and-iat', { token })
		const verifyResponse = await app.handle(verifyRequest)

		const verifiedResult = (await verifyResponse.json()) as {
			success: boolean
			data: { name: string; exp: number; iat: number } | null
		}

		expect(verifiedResult.success).toBe(true)
		expect(verifiedResult.data?.name).toBe(payloadToSign.name)
		expect(verifiedResult.data?.exp).toBeDefined()
		expect(verifiedResult.data?.iat).toBeDefined()
	})

	it('Should allow disabling default values', async () => {
		const payloadToSign = { name: 'John Doe' }

		const signRequest = post('/sign-token-disable-exp-and-iat', payloadToSign)
		const signResponse = await app.handle(signRequest)
		const token = await signResponse.text()

		expect(token.split('.').length).toBe(3)

		const verifyRequest = post('/verify-token', { token })
		const verifyResponse = await app.handle(verifyRequest)

		const verifiedResult = (await verifyResponse.json()) as {
			success: boolean
			data: { name: string; exp: undefined; iat: undefined } | null
		}

		expect(verifiedResult.success).toBe(true)
		expect(verifiedResult.data?.name).toBe(payloadToSign.name)
		expect(verifiedResult.data?.exp).toBeUndefined()
		expect(verifiedResult.data?.iat).toBeUndefined()
	})

	it('should sign and verify JWT with schema validation', async () => {
		const schemaApp = new Elysia()
			.use(
				jwt({
					name: 'jwtWithSchema',
					secret: TEST_SECRET,
					schema: t.Object({
						userId: t.String(),
						role: t.String(),
						permissions: t.Array(t.String())
					})
				})
			)
			.post(
				'/sign-with-schema',
				({ jwtWithSchema, body }) =>
					jwtWithSchema.sign({
						userId: body.userId,
						role: body.role,
						permissions: body.permissions,
						exp: '1h'
					}),
				{
					body: t.Object({
						userId: t.String(),
						role: t.String(),
						permissions: t.Array(t.String())
					})
				}
			)
			.post(
				'/verify-with-schema',
				async ({ jwtWithSchema, body }) => {
					const verifiedPayload = await jwtWithSchema.verify(body.token)
					if (!verifiedPayload) {
						return {
							success: false,
							data: null,
							message: 'Verification failed'
						}
					}
					return { success: true, data: verifiedPayload }
				},
				{
					body: t.Object({ token: t.String() })
				}
			)

		const payloadToSign = {
			userId: 'user123',
			role: 'admin',
			permissions: ['read', 'write', 'delete']
		}

		const signRequest = post('/sign-with-schema', payloadToSign)
		const signResponse = await schemaApp.handle(signRequest)
		const token = await signResponse.text()

		expect(token.split('.').length).toBe(3)

		const verifyRequest = post('/verify-with-schema', { token })
		const verifyResponse = await schemaApp.handle(verifyRequest)
		const verifiedResult = (await verifyResponse.json()) as {
			success: boolean
			data: { userId: string; role: string; permissions: string[]; exp: number; iat: number } | null
		}

		expect(verifiedResult.success).toBe(true)
		expect(verifiedResult.data?.userId).toBe(payloadToSign.userId)
		expect(verifiedResult.data?.role).toBe(payloadToSign.role)
		expect(verifiedResult.data?.permissions).toEqual(payloadToSign.permissions)
		expect(verifiedResult.data?.exp).toBeDefined()
		expect(verifiedResult.data?.iat).toBeDefined()
	})

	it('should sign and verify JWT with composite schema validation', async () => {
		const Role = {
			ADMIN: 'ADMIN',
			USER: 'USER',
		} as const

		const baseJwtSchema = t.Object({
			id: t.String(),
			sessionId: t.String(),
			roles: t.Array(t.Enum(Role)),
			verification: t.String(),
		})

		const accessJwtSchema = t.Composite([
			baseJwtSchema,
			t.Object({
				firstName: t.String(),
				lastName: t.String(),
				email: t.String(),
				phone: t.Optional(t.String()),
				company: t.Optional(t.String()),
			}),
		])

		const unionSchema = t.Union([baseJwtSchema, accessJwtSchema])
		type AccessTokenData = Static<typeof accessJwtSchema>;

		const compositeSchemaApp = new Elysia()
			.use(
				jwt({
					name: 'jwtWithComposite',
					secret: TEST_SECRET,
					schema: unionSchema
				})
			)
			.post(
				'/sign-with-composite',
				({ jwtWithComposite, body }) => {
					const payload = {
						id: body.id,
						sessionId: body.sessionId,
						roles: body.roles,
						verification: body.verification,
						firstName: body.firstName,
						lastName: body.lastName,
						email: body.email,
						phone: body.phone,
						company: body.company,
					} satisfies AccessTokenData;

					return jwtWithComposite.sign(payload);
				},
				{ body: accessJwtSchema }
			)
			.post(
				'/verify-with-composite',
				async ({ jwtWithComposite, body }) => {
					const verifiedPayload = await jwtWithComposite.verify(body.token)
					if (!verifiedPayload) {
						return {
							success: false,
							data: null,
							message: 'Verification failed'
						}
					}
					return { success: true, data: verifiedPayload }
				},
				{
					body: t.Object({ token: t.String() })
				}
			)

		const fullPayload = {
			id: 'user_123',
			sessionId: 'sess_456',
			roles: ['ADMIN', 'USER'],
			verification: 'verified',
			firstName: 'John',
			lastName: 'Doe',
			email: 'john.doe@example.com',
			phone: '+1234567890',
			company: 'Test Corp'
		}

		const signRequest = post('/sign-with-composite', fullPayload)
		const signResponse = await compositeSchemaApp.handle(signRequest)
		const token = await signResponse.text()

		expect(token.split('.').length).toBe(3)

		const verifyRequest = post('/verify-with-composite', { token })
		const verifyResponse = await compositeSchemaApp.handle(verifyRequest)
		const verifiedResult = await verifyResponse.json()

		expect(verifiedResult.success).toBe(true)
		expect(verifiedResult.data?.id).toBe(fullPayload.id)
		expect(verifiedResult.data?.sessionId).toBe(fullPayload.sessionId)
		expect(verifiedResult.data?.roles).toEqual(fullPayload.roles)
		expect(verifiedResult.data?.verification).toBe(fullPayload.verification)
		expect(verifiedResult.data?.firstName).toBe(fullPayload.firstName)
		expect(verifiedResult.data?.lastName).toBe(fullPayload.lastName)
		expect(verifiedResult.data?.email).toBe(fullPayload.email)
		expect(verifiedResult.data?.phone).toBe(fullPayload.phone)
		expect(verifiedResult.data?.company).toBe(fullPayload.company)
		expect(verifiedResult.data?.iat).toBeDefined()

		const minimalPayload = {
			id: 'user_789',
			sessionId: 'sess_012',
			roles: ['USER'],
			verification: 'pending',
			firstName: 'Jane',
			lastName: 'Smith',
			email: 'jane.smith@example.com'
		}

		const minimalSignRequest = post('/sign-with-composite', minimalPayload)
		const minimalSignResponse = await compositeSchemaApp.handle(minimalSignRequest)
		const minimalToken = await minimalSignResponse.text()

		const minimalVerifyRequest = post('/verify-with-composite', { token: minimalToken })
		const minimalVerifyResponse = await compositeSchemaApp.handle(minimalVerifyRequest)
		const minimalVerifiedResult = await minimalVerifyResponse.json()

		expect(minimalVerifiedResult.success).toBe(true)
		expect(minimalVerifiedResult.data?.id).toBe(minimalPayload.id)
		expect(minimalVerifiedResult.data?.sessionId).toBe(minimalPayload.sessionId)
		expect(minimalVerifiedResult.data?.roles).toEqual(minimalPayload.roles)
		expect(minimalVerifiedResult.data?.verification).toBe(minimalPayload.verification)
		expect(minimalVerifiedResult.data?.firstName).toBe(minimalPayload.firstName)
		expect(minimalVerifiedResult.data?.lastName).toBe(minimalPayload.lastName)
		expect(minimalVerifiedResult.data?.email).toBe(minimalPayload.email)
		expect(minimalVerifiedResult.data?.phone).toBeUndefined()
		expect(minimalVerifiedResult.data?.company).toBeUndefined()
	})
})
