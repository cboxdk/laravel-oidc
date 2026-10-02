<?php

declare(strict_types=1);

use Cbox\Oidc\Exceptions\OidcException;
use Cbox\Oidc\Support\CarbonClock;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;

arch('no debug calls left behind')
    ->expect(['dd', 'dump', 'ddd', 'ray', 'var_dump', 'print_r', 'echo'])
    ->not->toBeUsed();

arch('strict types everywhere')
    ->expect('Cbox\Oidc')
    ->toUseStrictTypes();

arch('exceptions extend the package base exception')
    ->expect('Cbox\Oidc\Exceptions')
    ->classes()
    ->toExtend(OidcException::class)
    ->ignoring(OidcException::class);

arch('configuration objects are readonly')
    ->expect('Cbox\Oidc\Config')
    ->classes()
    ->toBeReadonly();

arch('nothing reads the system clock directly; time comes from a PSR-20 clock')
    ->expect(['time', 'microtime', 'date', 'now', 'hrtime'])
    ->not->toBeUsed();

arch('no raw HTTP clients; every outbound call goes through the injected client')
    ->expect(['curl_init', 'curl_exec', 'file_get_contents', 'fopen', 'fsockopen', 'stream_socket_client'])
    ->not->toBeUsed();

arch('provider calls go through the HttpClient contract; only its default implementation touches an HTTP library')
    ->expect(['Illuminate\Http\Client', Http::class, 'GuzzleHttp', 'Psr\Http\Client'])
    ->toOnlyBeUsedIn('Cbox\Oidc\Http');

arch('the package reads time from the PSR-20 clock it is given; only CarbonClock reads Carbon')
    ->expect(['Carbon', Carbon::class])
    ->toOnlyBeUsedIn(CarbonClock::class);
