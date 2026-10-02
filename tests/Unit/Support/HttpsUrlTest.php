<?php

declare(strict_types=1);

use Cbox\Oidc\Support\HttpsUrl;

it('accepts an absolute https URL', function (string $url): void {
    expect(HttpsUrl::valid($url))->toBeTrue();
})->with([
    'plain' => ['https://idp.example.com/oauth/token'],
    'port and query' => ['https://idp.example.com:8443/keys?v=2'],
    'upper-case scheme' => ['HTTPS://idp.example.com/'],
    'Entra multi-tenant' => ['https://login.microsoftonline.com/organizations/discovery/v2.0/keys'],
]);

it('refuses anything else', function (mixed $url): void {
    expect(HttpsUrl::valid($url))->toBeFalse();
})->with([
    'http' => ['http://idp.example.com/token'],
    'relative' => ['/oauth/token'],
    'no host' => ['https:///token'],
    'user info' => ['https://user:pass@idp.example.com/token'],
    'fragment' => ['https://idp.example.com/token#x'],
    'whitespace' => ['https://idp.example.com/to ken'],
    'control character' => ["https://idp.example.com/\ntoken"],
    'javascript' => ['javascript:alert(1)'],
    'not a string' => [['https://idp.example.com']],
    'null' => [null],
    'empty' => [''],
    'too long' => ['https://idp.example.com/'.str_repeat('a', 2048)],
]);
