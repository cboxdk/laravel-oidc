<?php

declare(strict_types=1);

use Cbox\Oidc\Config\ConfigReader;
use Cbox\Oidc\Config\ConnectionConfig;
use Cbox\Oidc\Discovery\ProviderMetadata;
use Cbox\Oidc\Exceptions\DiscoveryFailed;
use Cbox\Oidc\Exceptions\ErrorCode;
use Cbox\Oidc\Tests\Support\ConnectionFixtures;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Cbox\Oidc\Tokens\SigningAlgorithm;

/**
 * @param  array<string, mixed>  $overrides
 */
function metadataConnection(array $overrides = []): ConnectionConfig
{
    return ConnectionConfig::fromConfig('main', ConfigReader::of(ConnectionFixtures::minimal($overrides), 'oidc.connections.main'));
}

/**
 * @param  array<string, mixed>  $changes  null removes a member
 * @return array<string, mixed>
 */
function discoveryDocument(array $changes = []): array
{
    return array_filter(array_replace(new FakeProvider()->discovery, $changes), static fn (mixed $value): bool => $value !== null);
}

it('reads a discovery document', function (): void {
    $metadata = ProviderMetadata::fromDocument(discoveryDocument(), metadataConnection());

    expect($metadata->issuer)->toBe('https://idp.example.test')
        ->and($metadata->authorizationEndpoint)->toBe('https://idp.example.test/oauth/authorize')
        ->and($metadata->tokenEndpoint)->toBe('https://idp.example.test/oauth/token')
        ->and($metadata->jwksUri)->toBe('https://idp.example.test/oauth/jwks')
        ->and($metadata->userinfoEndpoint)->toBe('https://idp.example.test/oauth/userinfo')
        ->and($metadata->endSessionEndpoint)->toBe('https://idp.example.test/oauth/logout')
        ->and($metadata->revocationEndpoint)->toBe('https://idp.example.test/oauth/revoke')
        ->and($metadata->signingAlgorithms)->toBe([SigningAlgorithm::RS256, SigningAlgorithm::ES256, SigningAlgorithm::EdDSA])
        ->and($metadata->supports(SigningAlgorithm::ES256))->toBeTrue()
        ->and($metadata->supports(SigningAlgorithm::PS256))->toBeFalse()
        ->and($metadata->authorizationResponseIssParameterSupported)->toBeTrue()
        ->and($metadata->backchannelLogoutSupported)->toBeTrue()
        ->and($metadata->backchannelLogoutSessionSupported)->toBeTrue()
        ->and($metadata->document['subject_types_supported'])->toBe(['public']);
});

it('reads a minimal document with defaults for what it leaves out', function (): void {
    $metadata = ProviderMetadata::fromDocument([
        'issuer' => 'https://idp.example.test',
        'authorization_endpoint' => 'https://idp.example.test/a',
        'token_endpoint' => 'https://idp.example.test/t',
        'jwks_uri' => 'https://idp.example.test/k',
        'id_token_signing_alg_values_supported' => ['RS256'],
    ], metadataConnection());

    expect($metadata->userinfoEndpoint)->toBeNull()
        ->and($metadata->endSessionEndpoint)->toBeNull()
        ->and($metadata->revocationEndpoint)->toBeNull()
        ->and($metadata->signingAlgorithms)->toBe([SigningAlgorithm::RS256])
        ->and($metadata->authorizationResponseIssParameterSupported)->toBeFalse()
        ->and($metadata->backchannelLogoutSupported)->toBeFalse();
});

it('keeps the connection\'s order of the common algorithms', function (): void {
    $metadata = ProviderMetadata::fromDocument(
        discoveryDocument(['id_token_signing_alg_values_supported' => ['EdDSA', 'HS256', 'none', 'RS256']]),
        metadataConnection(['algorithms' => ['RS256', 'PS256', 'EdDSA']]),
    );

    expect($metadata->signingAlgorithms)->toBe([SigningAlgorithm::RS256, SigningAlgorithm::EdDSA]);
});

it('matches a Microsoft Entra issuer template exactly', function (): void {
    $connection = ConnectionConfig::fromConfig('entra', ConfigReader::of(ConnectionFixtures::entraMultiTenant(), 'oidc.connections.entra'));
    $metadata = ProviderMetadata::fromDocument([
        'issuer' => 'https://login.microsoftonline.com/{tenantid}/v2.0',
        'authorization_endpoint' => 'https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize',
        'token_endpoint' => 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
        'jwks_uri' => 'https://login.microsoftonline.com/organizations/discovery/v2.0/keys',
        'id_token_signing_alg_values_supported' => ['RS256'],
        'token_endpoint_auth_methods_supported' => ['client_secret_post', 'private_key_jwt', 'client_secret_basic'],
    ], $connection);

    expect($metadata->issuer)->toBe('https://login.microsoftonline.com/{tenantid}/v2.0');
});

it('refuses a document for another issuer', function (string $issuer): void {
    expect(fn (): ProviderMetadata => ProviderMetadata::fromDocument(discoveryDocument(['issuer' => $issuer]), metadataConnection()))
        ->toThrow(function (DiscoveryFailed $exception) use ($issuer): void {
            expect($exception->errorCode())->toBe(ErrorCode::DiscoveryIssuerMismatch)
                ->and($exception->getMessage())->toContain(sprintf('names the issuer "%s", but the connection pins "https://idp.example.test"', $issuer))
                ->and($exception->fix())->toContain('set oidc.connections.main.issuer to it exactly');
        });
})->with([
    'another host' => ['https://evil.example.test'],
    'a trailing slash' => ['https://idp.example.test/'],
    'another case' => ['https://IDP.example.test'],
    'http' => ['http://idp.example.test'],
    'a tenant path' => ['https://idp.example.test/tenant-b'],
]);

it('refuses a document the flow cannot use', function (array $changes, string $problem, array $connection = []): void {
    expect(fn (): ProviderMetadata => ProviderMetadata::fromDocument(discoveryDocument($changes), metadataConnection($connection)))
        ->toThrow(function (DiscoveryFailed $exception) use ($problem): void {
            expect($exception->errorCode())->toBe(ErrorCode::DiscoveryInvalid)
                ->and($exception->getMessage())->toContain('The discovery document of connection "main" at https://idp.example.test/.well-known/openid-configuration '.$problem);
        });
})->with([
    'no issuer' => [['issuer' => null], 'has no issuer'],
    'an issuer that is not a string' => [['issuer' => ['https://idp.example.test']], 'has no issuer'],
    'no authorization endpoint' => [['authorization_endpoint' => null], 'has no authorization_endpoint'],
    'no token endpoint' => [['token_endpoint' => null], 'has no token_endpoint'],
    'no jwks_uri' => [['jwks_uri' => null], 'has no jwks_uri'],
    'an http jwks_uri' => [['jwks_uri' => 'http://idp.example.test/jwks'], 'has jwks_uri set to something other than an https URL'],
    'a relative token endpoint' => [['token_endpoint' => '/oauth/token'], 'has token_endpoint set to something other than an https URL'],
    'a javascript authorization endpoint' => [['authorization_endpoint' => 'javascript:alert(1)'], 'has authorization_endpoint set to something other than an https URL'],
    'an http userinfo endpoint' => [['userinfo_endpoint' => 'http://idp.example.test/me'], 'has userinfo_endpoint set to something other than an https URL'],
    'an end session endpoint with user info' => [['end_session_endpoint' => 'https://u:p@idp.example.test/logout'], 'has end_session_endpoint set to something other than an https URL'],
    'a revocation endpoint that is a number' => [['revocation_endpoint' => 42], 'has revocation_endpoint set to something other than an https URL'],
    'no signing algorithms' => [['id_token_signing_alg_values_supported' => null], 'has no id_token_signing_alg_values_supported'],
    'an empty algorithm list' => [['id_token_signing_alg_values_supported' => []], 'has no id_token_signing_alg_values_supported'],
    'an algorithm list with a number' => [['id_token_signing_alg_values_supported' => ['RS256', 1]], 'has no id_token_signing_alg_values_supported'],
    'only algorithms the connection refuses' => [['id_token_signing_alg_values_supported' => ['HS256', 'none', 'PS256']], 'lists no ID token algorithm the connection accepts (it lists HS256, none, PS256)', ['algorithms' => ['RS256', 'ES256']]],
    'no code response type' => [['response_types_supported' => ['id_token', 'token id_token']], 'does not support the authorization code flow'],
    'response types that are not a list' => [['response_types_supported' => 'code'], 'has response_types_supported set to something other than a list of strings'],
    'no PKCE S256' => [['code_challenge_methods_supported' => ['plain']], 'does not support PKCE with S256'],
    'not the client authentication in use' => [['token_endpoint_auth_methods_supported' => ['private_key_jwt']], 'does not support client_auth client_secret_basic'],
    'post without a methods list' => [['token_endpoint_auth_methods_supported' => null], 'lists no token_endpoint_auth_methods_supported, which means client_secret_basic only, but the connection uses client_secret_post', ['client_auth' => 'client_secret_post']],
]);

it('lets a public client ignore the client authentication methods', function (): void {
    $metadata = ProviderMetadata::fromDocument(
        discoveryDocument(['token_endpoint_auth_methods_supported' => ['private_key_jwt']]),
        metadataConnection(['client_auth' => 'none', 'client_secret' => null]),
    );

    expect($metadata->tokenEndpoint)->toBe('https://idp.example.test/oauth/token');
});

it('accepts client_secret_basic when the provider lists no methods', function (): void {
    expect(ProviderMetadata::fromDocument(discoveryDocument(['token_endpoint_auth_methods_supported' => null]), metadataConnection())->issuer)
        ->toBe('https://idp.example.test');
});

it('reads only true as true for the capability flags', function (): void {
    $metadata = ProviderMetadata::fromDocument(discoveryDocument([
        'authorization_response_iss_parameter_supported' => 'true',
        'backchannel_logout_supported' => 1,
        'backchannel_logout_session_supported' => false,
    ]), metadataConnection());

    expect($metadata->authorizationResponseIssParameterSupported)->toBeFalse()
        ->and($metadata->backchannelLogoutSupported)->toBeFalse()
        ->and($metadata->backchannelLogoutSessionSupported)->toBeFalse();
});
