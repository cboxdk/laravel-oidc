<?php

declare(strict_types=1);

namespace Cbox\Oidc\Support;

use Cbox\Oidc\Exceptions\InvalidProviderResponse;
use Cbox\Oidc\Exceptions\ProviderUnavailable;
use Cbox\Oidc\Http\HttpResponse;
use JsonException;

/**
 * Reads a JSON document a provider serves (discovery, key set) out of its
 * response.
 *
 * @internal
 */
final class ProviderDocument
{
    /**
     * The JSON object of a 200 response. A temporary failure (408, 429, 5xx)
     * is {@see ProviderUnavailable}; any other status, and a body that is not
     * one JSON object with unique keys, is {@see InvalidProviderResponse}.
     *
     * @return array<array-key, mixed>
     */
    public static function fromResponse(HttpResponse $response, string $url, string $what): array
    {
        if ($response->temporaryFailure()) {
            throw ProviderUnavailable::status($url, $response->status);
        }

        if ($response->status !== 200) {
            throw InvalidProviderResponse::status($url, $response->status);
        }

        return self::fromBody($response->body, $url, $what);
    }

    /**
     * @return array<array-key, mixed>
     */
    public static function fromBody(string $body, string $url, string $what): array
    {
        try {
            return StrictJson::decodeObject($body);
        } catch (JsonException $exception) {
            throw InvalidProviderResponse::malformed($url, $what, $exception->getMessage(), $exception);
        }
    }
}
