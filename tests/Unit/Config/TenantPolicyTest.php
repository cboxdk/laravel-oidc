<?php

declare(strict_types=1);

use Cbox\Oidc\Config\TenantPolicy;

it('compares Google domains and Entra tenant ids without case', function (string $claim, string $allowed, string $tenant): void {
    expect(new TenantPolicy($claim, [$allowed])->allows($tenant))->toBeTrue();
})->with([
    ['hd', 'example.com', 'EXAMPLE.com'],
    ['tid', '11111111-1111-1111-1111-11111111abcd', '11111111-1111-1111-1111-11111111ABCD'],
]);

it('compares any other tenant claim exactly', function (): void {
    $policy = new TenantPolicy('org', ['Acme']);

    expect($policy->allows('Acme'))->toBeTrue()
        ->and($policy->allows('acme'))->toBeFalse();
});

it('allows any tenant only when told to', function (): void {
    expect(new TenantPolicy('tid', ['*'])->allows('anything'))->toBeTrue()
        ->and(new TenantPolicy('tid', ['a'])->allows('*'))->toBeFalse()
        ->and(new TenantPolicy('hd', ['example.com'])->allows('evil.example.com'))->toBeFalse();
});
