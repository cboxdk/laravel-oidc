---
title: HTTP client and clock
description: Route the calls to providers through your own client, and give the package your own PSR-20 clock
weight: 26
---

# HTTP client and clock

## The HTTP client

Every call the package makes to a provider (discovery, keys, the token,
userinfo and revocation endpoints) goes through one contract,
`Cbox\Oidc\Contracts\HttpClient`:

<!-- signature: Cbox\Oidc\Contracts\HttpClient -->
```php
public function send(HttpRequest $request): HttpResponse;
```

The default, `Cbox\Oidc\Http\LaravelHttpClient`, sends through Laravel's HTTP
client, so `Http::fake()` answers it in your tests. It:

- puts the `cboxdk/laravel-ssrf` guard in the handler stack, https only, so the
  URL actually sent is checked and DNS-pinned (`oidc_http_blocked` when
  refused);
- never follows redirects: a 3xx comes back as a response, and the package
  refuses it;
- applies `oidc.http.timeout_seconds` and `connect_timeout_seconds`;
- caps the body at `oidc.http.max_response_bytes`, from `Content-Length`, while
  it downloads and once more at the end;
- never decompresses: it sends `Accept-Encoding: identity`, turns off curl's
  decoding, and refuses a response with another `Content-Encoding`, because a
  small gzip body can expand far past the cap.

To change how calls are sent, bind your own implementation in a service
provider's `register()`. It must keep those rules. The simplest way is to wrap
the default, as this client does to log every call:

<!-- example: http-client -->
```php
<?php

declare(strict_types=1);

use Cbox\Oidc\Contracts\HttpClient;
use Cbox\Oidc\Http\HttpRequest;
use Cbox\Oidc\Http\HttpResponse;
use Cbox\Oidc\Http\LaravelHttpClient;
use Psr\Log\LoggerInterface;

final readonly class LoggedHttpClient implements HttpClient
{
    public function __construct(
        private LaravelHttpClient $inner,
        private LoggerInterface $log,
    ) {}

    public function send(HttpRequest $request): HttpResponse
    {
        $response = $this->inner->send($request);

        // The URL only: form fields and headers can carry secrets.
        $this->log->info('OIDC provider call', [
            'method' => $request->method->value,
            'url' => $request->url,
            'status' => $response->status,
        ]);

        return $response;
    }
}
```

<!-- example: http-client-binding -->
```php
// app/Providers/AppServiceProvider.php, in register()
$this->app->singleton(\Cbox\Oidc\Contracts\HttpClient::class, LoggedHttpClient::class);
```

The test suite loads the example above, binds it and runs discovery through
it, so it stays correct.

The guard's own settings (blocked ranges, `enforce`) live in
`config/ssrf.php`; see the
[laravel-ssrf documentation](https://github.com/cboxdk/laravel-ssrf). In your
tests, give the provider's host a public address with its
`InteractsWithSsrf::fakeSsrfDns()`, or the guard refuses the faked call.

## The clock

The package reads time only from a PSR-20 `Psr\Clock\ClockInterface`: cache
freshness, the lifetime of started logins, client assertions and token
expiry. The default,
`Cbox\Oidc\Support\CarbonClock`, returns Carbon's now in UTC, so Laravel's
`$this->travel()`, `travelTo()` and `freezeTime()` move it in your tests.

When the application binds its own `ClockInterface`, the package uses that
one instead; it binds `CarbonClock` only when nothing else is bound.
