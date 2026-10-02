<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tests\Support;

use Cbox\Oidc\Config\CacheConfig;
use Cbox\Oidc\Config\FlowConfig;
use Cbox\Oidc\Config\HttpConfig;
use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Contracts\HttpClient;
use Cbox\Oidc\Contracts\OidcClient;
use Cbox\Oidc\Diagnostics\ConnectionDiagnostics;
use Cbox\Oidc\Discovery\MetadataRepository;
use Cbox\Oidc\Exceptions\ErrorCode;
use Cbox\Oidc\Exceptions\OidcException;
use Cbox\Oidc\Exceptions\TokenRejected;
use Cbox\Oidc\Flow\AuthorizationFlow;
use Cbox\Oidc\Keys\KeySetRepository;
use Cbox\Oidc\Keys\SigningKeys;
use Cbox\Oidc\Logout\LogoutFlow;
use Cbox\Oidc\Logout\LogoutTokenVerifier;
use Cbox\Oidc\Tokens\ClaimChecks;
use Cbox\Oidc\Tokens\IdTokenVerifier;
use Cbox\Oidc\Tokens\SignedJwtReader;
use Cbox\Oidc\Tokens\TokenEndpoint;
use Cbox\Oidc\Tokens\TokenRefresher;
use Cbox\Oidc\Tokens\TokenRevocation;
use Cbox\Oidc\UserInfo\UserInfoEndpoint;
use Closure;
use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\Assert;

/**
 * Assertions shared by the feature tests.
 */
final class Refusals
{
    /**
     * Runs $call and checks that it throws $class with $code, a message that
     * contains $message, and, for a token refusal, the claim $claim.
     *
     * @param  class-string<OidcException>  $class
     */
    public static function assert(Closure $call, ErrorCode $code, string $class, string $message = '', ?string $claim = null): OidcException
    {
        try {
            $call();
        } catch (OidcException $exception) {
            expect($exception)->toBeInstanceOf($class)
                ->and($exception->errorCode())->toBe($code)
                ->and($exception->getMessage())->toContain($message);

            if ($exception instanceof TokenRejected) {
                expect($exception->claim())->toBe($claim);
            }

            return $exception;
        }

        Assert::fail(sprintf('Expected %s (%s), but nothing was thrown.', $class, $code->value));
    }

    /**
     * Replaces connection $name and drops every service built from the old
     * configuration.
     *
     * @param  array<string, mixed>  $values
     */
    public static function useConnection(string $name, array $values): void
    {
        config(['oidc.connections.'.$name => $values]);
        self::forgetServices();
    }

    /**
     * Drops every service built from the configuration, so the next call
     * reads config('oidc') again.
     */
    public static function forgetServices(): void
    {
        foreach ([
            OidcConfig::class, HttpConfig::class, CacheConfig::class, FlowConfig::class, HttpClient::class,
            MetadataRepository::class, KeySetRepository::class, SigningKeys::class, TokenEndpoint::class,
            SignedJwtReader::class, ClaimChecks::class, IdTokenVerifier::class, AuthorizationFlow::class,
            TokenRefresher::class, TokenRevocation::class, UserInfoEndpoint::class, LogoutFlow::class,
            LogoutTokenVerifier::class, ConnectionDiagnostics::class, OidcClient::class,
        ] as $service) {
            app()->forgetInstance($service);
        }

        Facade::clearResolvedInstance(OidcClient::class);
    }
}
