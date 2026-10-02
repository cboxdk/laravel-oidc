<?php

declare(strict_types=1);

use Cbox\Oidc\Support\Base64Url;

it('round-trips bytes of every length', function (int $length): void {
    $bytes = $length === 0 ? '' : random_bytes($length);

    expect(Base64Url::decode(Base64Url::encode($bytes)))->toBe($bytes);
})->with([0, 1, 2, 3, 4, 31, 32, 33]);

it('decodes only canonical unpadded base64url', function (string $encoded): void {
    expect(Base64Url::decode($encoded))->toBeNull();
})->with([
    'padding' => ['YQ=='],
    'the standard alphabet' => ['+/8'],
    'whitespace' => ['YW Jj'],
    'a length no encoding has' => ['YWJjZ'],
    'unused bits set' => ['YR'],
    'a newline at the end' => ["YQ\n"],
]);
