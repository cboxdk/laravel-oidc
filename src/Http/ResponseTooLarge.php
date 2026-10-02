<?php

declare(strict_types=1);

namespace Cbox\Oidc\Http;

use Cbox\Oidc\Exceptions\InvalidProviderResponse;
use RuntimeException;

/**
 * Thrown from Guzzle's on_headers and progress callbacks to abort a transfer
 * that passes the size limit; {@see LaravelHttpClient} turns it into
 * {@see InvalidProviderResponse}.
 *
 * @internal
 */
final class ResponseTooLarge extends RuntimeException {}
