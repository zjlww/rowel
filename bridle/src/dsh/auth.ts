/**
 * The browser session cookie dsh 0.2 requires, obtained from the rotating login
 * token the deployment maintains.
 *
 * dsh 0.1.x had no authentication: the fence was a loopback bind plus a Host
 * header check, and anything on this machine could call `/api`. 0.2 put a signed
 * browser cookie in front of `/api` — even on loopback — and mints it from a
 * process token printed in the URL `dsh web` announces at startup.
 *
 * A per-process token is useless to a daemon that outlives it, which is why
 * 0.2's client-connection reads `$RUNTIME_DIRECTORY/login-token` when the
 * deployment provides one (see the `webLoginToken` helper dsh ships). A systemd
 * unit with `RuntimeDirectory=` gives a deployment a tmpfs file it can rotate on
 * its own schedule; the cookie minted from it stays valid for the deployment's
 * `cookieMaxAgeDays` (30 by default) because it is signed with a secret that
 * lives in the harness home, not in the process.
 *
 * So this class is deliberately small: read a token file, exchange it for a
 * cookie, hand the cookie header to whoever needs it, and forget it when the
 * server says it is no longer good. Nothing here is persisted — a cookie is a
 * bearer credential and Bridle has no reason to keep one on disk.
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

/**
 * The shape dsh itself validates a login token against.
 *
 * Mirrored rather than loosened: a truncated or half-written file should be
 * reported as "no token yet" instead of being sent to dsh as a guess.
 */
const LOGIN_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/u

/** Cookie name prefix dsh uses; the suffix is a hash of the request authority. */
const COOKIE_PREFIX = 'dsh-auth-'

/** Options for {@link DshCookieAuth}. */
export interface DshCookieAuthOptions {
  /** Loopback base URL of the harness the cookie is minted for. */
  base: URL
  /** Rotating login token file, when the caller knows where it is. */
  tokenFile?: string
  /** Progress reporting; never receives token or cookie values. */
  log?: (message: string) => void
}

/** A login token that has been exchanged for the cookie dsh will accept. */
export class DshCookieAuth {
  private cookie: string | undefined
  private mintedAt: number | undefined

  /** @param options - the harness base URL and where its login token lives. */
  constructor(private readonly options: DshCookieAuthOptions) {}

  /** The token file this instance reads, or undefined when there is none. */
  get tokenFile(): string | undefined {
    return this.options.tokenFile ?? discoverTokenFile()
  }

  /**
   * The `Cookie` header to send, minting a fresh cookie when there is none.
   * @returns the header value, or undefined when no token file is configured or
   *   readable — the caller then makes the request unauthenticated and reports
   *   whatever dsh says.
   */
  async header(): Promise<string | undefined> {
    if (this.cookie !== undefined) return this.cookie
    const path = this.tokenFile
    if (path === undefined) return undefined
    let token: string
    try {
      token = readFileSync(path, 'utf8').trim()
    } catch (error) {
      this.options.log?.(`dsh auth: cannot read ${path}: ${describe(error)}`)
      return undefined
    }
    if (!LOGIN_TOKEN_PATTERN.test(token)) {
      this.options.log?.(`dsh auth: ${path} does not hold a login token yet`)
      return undefined
    }
    const minted = await this.mint(token)
    if (minted === undefined) return undefined
    this.cookie = minted
    this.mintedAt = Date.now()
    return this.cookie
  }

  /** Drop a cookie dsh has rejected, so the next call mints another one. */
  invalidate(): void {
    this.cookie = undefined
    this.mintedAt = undefined
  }

  /** When the current cookie was minted, for diagnostics. */
  get age(): number | undefined {
    return this.mintedAt === undefined ? undefined : Date.now() - this.mintedAt
  }

  /**
   * Exchange one login token for a session cookie.
   *
   * The exchange is a `GET /?token=…` that answers 303 with `Set-Cookie`; the
   * redirect is not followed, because the cookie is in the redirect's own
   * headers and following it would only fetch the index page.
   * @param token - the rotating login token read from disk.
   * @returns the cookie header value, or undefined when dsh refused the token.
   */
  private async mint(token: string): Promise<string | undefined> {
    const url = new URL(this.options.base.origin)
    url.pathname = '/'
    url.searchParams.set('token', token)
    let response: Response
    try {
      response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(MINT_TIMEOUT_MS) })
    } catch (error) {
      this.options.log?.(`dsh auth: the token exchange failed: ${describe(error)}`)
      return undefined
    }
    if (response.status !== 303) {
      // 401 means the token on disk is not the one this process accepts — a
      // rotation the deployment has not finished, or a cookie secret that
      // changed under us. Either way the answer is a new token, not a retry.
      this.options.log?.(`dsh auth: the token exchange answered HTTP ${String(response.status)}`)
      return undefined
    }
    const jar = typeof response.headers.getSetCookie === 'function' ? response.headers.getSetCookie() : []
    for (const entry of jar) {
      const [pair] = entry.split(';')
      if (pair !== undefined && pair.startsWith(COOKIE_PREFIX)) return pair.trim()
    }
    this.options.log?.('dsh auth: the token exchange set no session cookie')
    return undefined
  }
}

/** How long the token exchange may take before it is abandoned. */
const MINT_TIMEOUT_MS = 10_000

/**
 * Where the login token usually is when nothing was configured.
 *
 * `$XDG_RUNTIME_DIR/dsh-web/login-token` is the shape a systemd user unit with
 * `RuntimeDirectory=dsh-web` produces, which is how the deployments this fork
 * serves are built. `$RUNTIME_DIRECTORY` is honoured too, so a Bridle started
 * from inside the unit's own environment finds the token without being told.
 * @returns the first existing candidate, or undefined when none is configured.
 */
export function discoverTokenFile(): string | undefined {
  const candidates: string[] = []
  const runtimeDirectory = process.env['RUNTIME_DIRECTORY']
  if (runtimeDirectory !== undefined && runtimeDirectory.length > 0) {
    candidates.push(join(runtimeDirectory, 'login-token'))
  }
  const xdg = process.env['XDG_RUNTIME_DIR']
  if (xdg !== undefined && xdg.length > 0) {
    candidates.push(join(xdg, 'dsh-web', 'login-token'))
  }
  for (const candidate of candidates) {
    try {
      readFileSync(candidate, { encoding: 'utf8', flag: 'r' })
      return candidate
    } catch {
      // Not this one; a candidate that does not exist is not an error.
    }
  }
  return undefined
}

/** Flatten an error and its causes, as the rest of the dsh client does. */
function describe(error: unknown): string {
  if (!(error instanceof Error)) return String(error)
  const chain: string[] = []
  let current: unknown = error
  while (current instanceof Error && chain.length < 4) {
    if (chain.at(-1) !== current.message) chain.push(current.message)
    current = current.cause
  }
  return chain.join(': ')
}
