<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tests\Support;

use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Exceptions\ErrorCode;
use Cbox\Oidc\Exceptions\OidcException;
use Cbox\Oidc\Exceptions\TokenRejected;
use Cbox\Oidc\Flow\AuthorizationFlow;
use Cbox\Oidc\Logout\LogoutFlow;
use Cbox\Oidc\Logout\LogoutTokenVerifier;
use Cbox\Oidc\Tokens\IdTokenVerifier;
use Cbox\Oidc\Tokens\TokenRefresher;
use Cbox\Oidc\Tokens\TokenRevocation;
use Cbox\Oidc\UserInfo\UserInfoEndpoint;
use Closure;
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

        foreach ([OidcConfig::class, IdTokenVerifier::class, AuthorizationFlow::class, TokenRefresher::class, TokenRevocation::class, UserInfoEndpoint::class, LogoutFlow::class, LogoutTokenVerifier::class] as $service) {
            app()->forgetInstance($service);
        }
    }
}
