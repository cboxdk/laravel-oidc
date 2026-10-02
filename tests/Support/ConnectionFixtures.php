<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tests\Support;

use Cbox\Oidc\Config\OidcConfig;
use Illuminate\Http\Request;

/**
 * Connection arrays as an application writes them in config/oidc.php.
 */
final class ConnectionFixtures
{
    /**
     * @param  array<string, mixed>  $overrides
     * @return array<string, mixed>
     */
    public static function minimal(array $overrides = []): array
    {
        return array_replace([
            'issuer' => 'https://idp.example.test',
            'client_id' => 'client-1',
            'client_secret' => 'secret-1',
            'redirect_uri' => 'https://app.example.test/oidc/callback',
        ], $overrides);
    }

    /**
     * The callback request a provider's redirect makes: a GET of the
     * connection's redirect_uri with $query.
     *
     * @param  array<string, mixed>  $query
     */
    public static function callbackRequest(array $query, ?string $connection = null): Request
    {
        return Request::create(resolve(OidcConfig::class)->connection($connection)->redirectUri, 'GET', $query);
    }

    /**
     * @return array<string, mixed>
     */
    public static function google(): array
    {
        return [
            'issuer' => 'https://accounts.google.com',
            'client_id' => 'google-client',
            'client_secret' => 'google-secret',
            'redirect_uri' => 'https://app.example.test/oidc/workspace/callback',
            'scopes' => ['openid', 'email', 'profile'],
            'algorithms' => ['RS256'],
            'tenant' => ['claim' => 'hd', 'allowed' => ['example.com']],
            'groups' => ['source' => 'none'],
            'authorization_parameters' => ['access_type' => 'offline', 'prompt' => 'consent'],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public static function entraMultiTenant(): array
    {
        return [
            'issuer' => 'https://login.microsoftonline.com/{tenantid}/v2.0',
            'discovery_url' => 'https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration',
            'client_id' => '00000000-0000-0000-0000-000000000001',
            'client_secret' => 'entra-secret',
            'redirect_uri' => 'https://app.example.test/oidc/entra/callback',
            'tenant' => ['claim' => 'tid', 'allowed' => ['11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222']],
        ];
    }
}
