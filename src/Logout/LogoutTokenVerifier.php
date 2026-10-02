<?php

declare(strict_types=1);

namespace Cbox\Oidc\Logout;

use Cbox\Oidc\Config\ConnectionConfig;
use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Discovery\MetadataRepository;
use Cbox\Oidc\Exceptions\LogoutTokenRejected;
use Cbox\Oidc\Exceptions\OidcException;
use Cbox\Oidc\Exceptions\TokenRejected;
use Cbox\Oidc\Tokens\ClaimChecks;
use Cbox\Oidc\Tokens\SignedJwtReader;
use Cbox\Oidc\Tokens\TokenKind;
use SensitiveParameter;
use stdClass;

/**
 * Verifies a logout token (OpenID Connect Back-Channel Logout 1.0, 2.6). A
 * logout token ends sessions, so a forged or replayed one would sign people
 * out at will, and an ID token accepted as one would let anyone who saw an ID
 * token sign its owner out. The checks run in this order, and the first that
 * fails throws a {@see TokenRejected} with its own code:
 *
 *  1. form, header, alg, key and signature, as for an ID token, with a typ
 *     of logout+jwt, JWT or none ({@see TokenKind::LogoutToken});
 *  2. iss, aud and azp, exp, nbf and iat (with max_token_age_seconds), as for
 *     an ID token;
 *  3. events is a JSON object with the member
 *     http://schemas.openid.net/event/backchannel-logout, whose value is a
 *     JSON object;
 *  4. there is no nonce: a logout token must never carry one, so an ID token
 *     cannot pass as one;
 *  5. sub, sid or both are present, each 1 to 255 characters;
 *  6. jti is present, 1 to 255 characters;
 *  7. the jti was not accepted before ({@see LogoutTokenRejected::replayed()}).
 *     It is remembered until exp plus the leeway. Checked last, so a token
 *     refused for another reason does not use up its jti.
 *
 * Rules 3 to 7 fail with {@see LogoutTokenRejected}.
 */
final readonly class LogoutTokenVerifier
{
    public const string EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    private const TokenKind KIND = TokenKind::LogoutToken;

    public function __construct(
        private OidcConfig $config,
        private MetadataRepository $metadata,
        private SignedJwtReader $reader,
        private ClaimChecks $checks,
        private LogoutTokenReplayGuard $replays,
    ) {}

    /**
     * @param  ConnectionConfig|string|null  $connection  a connection, its name, or null for the default
     *
     * @throws TokenRejected
     * @throws OidcException when discovery or the key set cannot be loaded, or no key fits
     */
    public function verify(ConnectionConfig|string|null $connection, #[SensitiveParameter] string $logoutToken): LogoutToken
    {
        $config = $connection instanceof ConnectionConfig ? $connection : $this->config->connection($connection);
        $name = $config->name;
        $metadata = $this->metadata->for($config);
        $jwt = $this->reader->read($config, $metadata, self::KIND, $logoutToken);
        $claims = $jwt->claims;

        $issuer = $this->checks->issuer(self::KIND, $config, $metadata, $claims, $jwt->key);
        $this->checks->audience(self::KIND, $config, $claims);
        [$issuedAt, $expiresAt] = $this->checks->lifetime(self::KIND, $config, $claims);
        $this->events($name, $jwt->payload);

        if (array_key_exists('nonce', $claims)) {
            throw LogoutTokenRejected::invalid($name, 'nonce', 'has a nonce, which a logout token must never carry, so this may be an ID token offered in its place');
        }

        $subject = $this->checks->subject(self::KIND, $name, $claims, required: false);
        $sessionId = $claims['sid'] ?? null;

        if ($sessionId !== null && ! ClaimChecks::validIdentifier($sessionId)) {
            throw LogoutTokenRejected::invalid($name, 'sid', 'has a sid that is not 1 to 255 characters without control characters');
        }

        if ($subject === null && $sessionId === null) {
            throw LogoutTokenRejected::invalid($name, 'sub', 'names neither a sub nor a sid, so it names no session to end');
        }

        $jti = $claims['jti'] ?? null;

        if (! ClaimChecks::validIdentifier($jti)) {
            throw LogoutTokenRejected::invalid($name, 'jti', 'has no jti, or one that is not 1 to 255 characters without control characters');
        }

        /** @var string $jti */
        /** @var string|null $sessionId */
        if (! $this->replays->claim($name, $issuer, $jti, $expiresAt, $config->leewaySeconds)) {
            throw LogoutTokenRejected::replayed($name);
        }

        return new LogoutToken(
            connection: $name,
            issuer: $issuer,
            subject: $subject,
            sessionId: $sessionId,
            jti: $jti,
            issuedAt: ClaimChecks::date($issuedAt),
            expiresAt: ClaimChecks::date($expiresAt),
            claims: $claims,
        );
    }

    /**
     * The events claim, read from the payload text so a JSON object is told
     * apart from an array.
     */
    private function events(string $connection, string $payload): void
    {
        $document = json_decode($payload, false, 16);
        $events = $document instanceof stdClass && property_exists($document, 'events') ? $document->events : null;

        if (! $events instanceof stdClass) {
            throw LogoutTokenRejected::invalid($connection, 'events', 'has no events claim, or one that is not a JSON object');
        }

        if (! property_exists($events, self::EVENT)) {
            throw LogoutTokenRejected::invalid($connection, 'events', sprintf('has no %s event', self::EVENT));
        }

        if (! $events->{self::EVENT} instanceof stdClass) {
            throw LogoutTokenRejected::invalid($connection, 'events', 'has a back-channel logout event whose value is not a JSON object');
        }
    }
}
