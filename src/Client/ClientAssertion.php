<?php

declare(strict_types=1);

namespace Cbox\Oidc\Client;

use Cbox\Oidc\Config\AssertionAudience;
use Cbox\Oidc\Config\ClientAssertionConfig;
use Cbox\Oidc\Config\ConnectionConfig;
use Cbox\Oidc\Discovery\ProviderMetadata;
use Cbox\Oidc\Support\Base64Url;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use LogicException;
use Psr\Clock\ClockInterface;

/**
 * Signs the client assertion of private_key_jwt client authentication (RFC
 * 7523 2.2 and 3, OpenID Connect Core 9) with web-token.
 *
 * Claims: iss and sub are the client id, aud the URL of the endpoint the
 * assertion is sent to (or the issuer, when configured), jti a fresh random
 * value, and iat, nbf and exp from the clock, valid for
 * client_assertion.lifetime_seconds.
 *
 * The audience is bound to where the assertion goes, so a provider that
 * names another party's URL as one of its endpoints never receives an
 * assertion that party accepts.
 *
 * @internal Not part of the public API; it may change in any release.
 */
final readonly class ClientAssertion
{
    public const string TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    public function __construct(
        private ClockInterface $clock,
    ) {}

    /**
     * @param  string  $endpoint  the URL the assertion is sent to
     */
    public function sign(ConnectionConfig $connection, ProviderMetadata $metadata, string $endpoint): string
    {
        $config = $connection->clientAssertion ?? throw new LogicException(sprintf('Connection "%s" does not use private_key_jwt.', $connection->name));
        $now = $this->clock->now()->getTimestamp();

        $claims = [
            'iss' => $connection->clientId,
            'sub' => $connection->clientId,
            'aud' => $config->audience === AssertionAudience::Issuer ? $metadata->issuer : $endpoint,
            'jti' => Base64Url::random(32),
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + $config->lifetimeSeconds,
        ];

        $jws = new JWSBuilder(new AlgorithmManager([$config->algorithm->signatureAlgorithm()]))
            ->create()
            ->withPayload(json_encode($claims, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES))
            ->addSignature($config->key, $this->header($config))
            ->build();

        return new CompactSerializer()->serialize($jws, 0);
    }

    /**
     * @return array<string, string>
     */
    private function header(ClientAssertionConfig $config): array
    {
        $header = ['alg' => $config->algorithm->value, 'typ' => 'JWT'];

        if ($config->keyId !== null) {
            $header['kid'] = $config->keyId;
        }

        return [...$header, ...$config->headers];
    }
}
