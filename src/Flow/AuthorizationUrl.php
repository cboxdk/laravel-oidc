<?php

declare(strict_types=1);

namespace Cbox\Oidc\Flow;

use Cbox\Oidc\Config\ConnectionConfig;
use Cbox\Oidc\Discovery\ProviderMetadata;
use Cbox\Oidc\Exceptions\DiscoveryFailed;

/**
 * Builds the authorization request URL (OpenID Connect Core 3.1.2.1, RFC
 * 7636). A pure function of the connection, the provider's metadata, the
 * transaction and the options.
 *
 * The parameters, in order: the protocol's own (response_type, client_id,
 * redirect_uri, scope, state, nonce, code_challenge, code_challenge_method),
 * then max_age, prompt, login_hint and acr_values when set, then the
 * options' parameters, then the connection's authorization_parameters that
 * neither replaced.
 *
 * @internal
 */
final class AuthorizationUrl
{
    public static function build(ConnectionConfig $connection, ProviderMetadata $metadata, AuthorizationTransaction $transaction, AuthorizationOptions $options): string
    {
        $scopes = array_values(array_unique([...$connection->scopes, ...$options->scopes]));

        $parameters = [
            'response_type' => 'code',
            'client_id' => $connection->clientId,
            'redirect_uri' => $transaction->redirectUri,
            'scope' => implode(' ', $scopes),
            'state' => $transaction->state,
            'nonce' => $transaction->nonce,
            'code_challenge' => Pkce::challenge($transaction->codeVerifier),
            'code_challenge_method' => Pkce::METHOD,
        ];

        if ($transaction->maxAge !== null) {
            $parameters['max_age'] = (string) $transaction->maxAge;
        }

        if ($options->prompts !== []) {
            $parameters['prompt'] = implode(' ', array_map(static fn (Prompt $prompt): string => $prompt->value, $options->prompts));
        }

        if ($options->loginHint !== null) {
            $parameters['login_hint'] = $options->loginHint;
        }

        if ($options->acrValues !== []) {
            $parameters['acr_values'] = implode(' ', $options->acrValues);
        }

        $parameters += $options->parameters;
        $parameters += $connection->authorizationParameters;

        return self::append($connection, $metadata->authorizationEndpoint, $parameters);
    }

    /**
     * Adds $parameters to the endpoint's own query, which RFC 6749 3.1 says
     * to keep. A parameter the endpoint already carries would be sent twice,
     * which the RFC forbids, so that endpoint is refused.
     *
     * @param  array<string, string>  $parameters
     */
    private static function append(ConnectionConfig $connection, string $endpoint, array $parameters): string
    {
        $query = parse_url($endpoint, PHP_URL_QUERY);

        if (is_string($query) && $query !== '') {
            parse_str($query, $existing);
            $twice = array_intersect(array_map(strtolower(...), array_map(strval(...), array_keys($existing))), array_map(strtolower(...), array_keys($parameters)));

            if ($twice !== []) {
                throw DiscoveryFailed::invalid($connection->name, $connection->discoveryUrl, sprintf('has an authorization_endpoint whose query already sets %s', implode(', ', $twice)), 'Remove the parameter from the endpoint at the provider, or from the connection\'s authorization_parameters.');
            }
        }

        $separator = is_string($query) && $query !== '' ? '&' : (str_ends_with($endpoint, '?') ? '' : '?');

        return $endpoint.$separator.http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
    }
}
