<?php

declare(strict_types=1);

namespace Cbox\Oidc\Client;

use Cbox\Oidc\Config\ClientAuthMethod;
use Cbox\Oidc\Config\ConnectionConfig;
use Cbox\Oidc\Discovery\ProviderMetadata;
use Cbox\Oidc\Http\HttpRequest;
use SensitiveParameter;

/**
 * Builds a form POST to one of the provider's client-authenticated
 * endpoints (token, revocation) with the connection's client
 * authentication (OpenID Connect Core 9):
 *
 * - client_secret_basic: HTTP Basic, with the id and secret each
 *   form-urlencoded first, as RFC 6749 2.3.1 says;
 * - client_secret_post: client_id and client_secret in the form;
 * - private_key_jwt: client_id, client_assertion_type and a fresh
 *   client_assertion in the form;
 * - none: client_id in the form, for a public client.
 */
final readonly class ClientAuthentication
{
    public function __construct(
        private ClientAssertion $assertion,
    ) {}

    /**
     * @param  array<string, string>  $form
     */
    public function request(ConnectionConfig $connection, ProviderMetadata $metadata, string $url, #[SensitiveParameter] array $form): HttpRequest
    {
        $headers = ['Accept' => 'application/json'];

        switch ($connection->clientAuth) {
            case ClientAuthMethod::ClientSecretBasic:
                $headers['Authorization'] = 'Basic '.base64_encode(urlencode($connection->clientId).':'.urlencode((string) $connection->clientSecret));
                break;
            case ClientAuthMethod::ClientSecretPost:
                $form['client_id'] = $connection->clientId;
                $form['client_secret'] = (string) $connection->clientSecret;
                break;
            case ClientAuthMethod::PrivateKeyJwt:
                $form['client_id'] = $connection->clientId;
                $form['client_assertion_type'] = ClientAssertion::TYPE;
                $form['client_assertion'] = $this->assertion->sign($connection, $metadata);
                break;
            case ClientAuthMethod::None:
                $form['client_id'] = $connection->clientId;
                break;
        }

        return HttpRequest::postForm($url, $form, $headers);
    }
}
