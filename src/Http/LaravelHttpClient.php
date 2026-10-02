<?php

declare(strict_types=1);

namespace Cbox\Oidc\Http;

use Cbox\Oidc\Config\HttpConfig;
use Cbox\Oidc\Contracts\HttpClient;
use Cbox\Oidc\Exceptions\InvalidProviderResponse;
use Cbox\Oidc\Exceptions\OutboundRequestBlocked;
use Cbox\Oidc\Exceptions\ProviderUnavailable;
use Cbox\Ssrf\Exceptions\BlockedUrl;
use Cbox\Ssrf\Http\GuardRequestMiddleware;
use Closure;
use GuzzleHttp\Exception\TransferException;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\HttpClientException;
use Illuminate\Http\Client\Response;
use Psr\Http\Message\ResponseInterface;
use Throwable;

/**
 * The default {@see HttpClient}: Laravel's HTTP client (so Http::fake() works
 * in your tests) with the cboxdk/laravel-ssrf guard in its handler stack.
 *
 * - The guard checks and DNS-pins the URL actually sent, https only (plain
 *   http too only when a connection sets allow_insecure_http, which a local or
 *   testing environment alone accepts).
 * - Redirects are never followed.
 * - Timeouts and the body size limit come from oidc.http. The size is checked
 *   from Content-Length, while the body downloads, and once more at the end.
 * - Bodies are never decompressed: the request asks for identity encoding,
 *   curl is told not to decode, and a response with any other
 *   Content-Encoding is refused. A small gzip body could otherwise expand
 *   past the size limit, which counts the bytes on the wire.
 */
final readonly class LaravelHttpClient implements HttpClient
{
    public function __construct(
        private Factory $http,
        private HttpConfig $config,
    ) {}

    public function send(HttpRequest $request): HttpResponse
    {
        $pending = $this->http
            ->withOptions(['allow_redirects' => false, 'decode_content' => false, ...self::sizeLimitOptions($this->config->maxResponseBytes)])
            ->withMiddleware(new GuardRequestMiddleware($this->config->allowInsecureHttp ? ['http', 'https'] : ['https']))
            ->timeout($this->config->timeoutSeconds)
            ->connectTimeout($this->config->connectTimeoutSeconds)
            ->withHeaders([...$request->headers, 'Accept-Encoding' => 'identity']);

        try {
            $response = match ($request->method) {
                HttpMethod::Get => $pending->get($request->url),
                HttpMethod::Post => $pending->asForm()->post($request->url, $request->form),
            };
        } catch (BlockedUrl|HttpClientException|TransferException $exception) {
            throw $this->translate($request->url, $exception);
        }

        return $this->toResponse($request->url, $response);
    }

    /**
     * Guzzle options that abort a transfer once it passes $limit bytes: from
     * Content-Length before the body arrives, and while it downloads.
     *
     * @return array{on_headers: Closure(ResponseInterface): void, progress: Closure(int|float, int|float): void}
     */
    public static function sizeLimitOptions(int $limit): array
    {
        return [
            'on_headers' => static function (ResponseInterface $response) use ($limit): void {
                $length = $response->getHeaderLine('Content-Length');

                if ($length !== '' && ctype_digit($length) && (int) $length > $limit) {
                    throw new ResponseTooLarge;
                }
            },
            'progress' => static function (int|float $expected, int|float $downloaded) use ($limit): void {
                if ($downloaded > $limit) {
                    throw new ResponseTooLarge;
                }
            },
        ];
    }

    private function toResponse(string $url, Response $response): HttpResponse
    {
        $body = $response->body();

        if (strlen($body) > $this->config->maxResponseBytes) {
            throw InvalidProviderResponse::tooLarge($url, $this->config->maxResponseBytes);
        }

        $headers = [];

        foreach ($response->toPsrResponse()->getHeaders() as $name => $values) {
            $headers[strtolower($name)] = implode(', ', $values);
        }

        $encoding = strtolower(trim($headers['content-encoding'] ?? ''));

        if ($encoding !== '' && $encoding !== 'identity') {
            throw InvalidProviderResponse::encoded($url, $encoding);
        }

        return new HttpResponse($response->status(), $headers, $body);
    }

    private function translate(string $url, Throwable $exception): Throwable
    {
        for ($cause = $exception; $cause instanceof Throwable; $cause = $cause->getPrevious()) {
            if ($cause instanceof BlockedUrl) {
                return OutboundRequestBlocked::url($url, $cause);
            }

            if ($cause instanceof ResponseTooLarge) {
                return InvalidProviderResponse::tooLarge($url, $this->config->maxResponseBytes);
            }
        }

        return ProviderUnavailable::unreachable($url, $exception);
    }
}
