<?php

declare(strict_types=1);

use Cbox\Oidc\Support\StrictJson;

it('decodes a JSON object', function (): void {
    expect(StrictJson::decodeObject(' {"a": 1, "b": {"c": [1, {"d": "x"}]}, "e": "q\"\\\\"} '))
        ->toBe(['a' => 1, 'b' => ['c' => [1, ['d' => 'x']]], 'e' => 'q"\\']);
});

it('decodes an empty object', function (): void {
    expect(StrictJson::decodeObject('{}'))->toBe([]);
});

it('allows the same key in different objects', function (): void {
    expect(StrictJson::decodeObject('{"a": {"k": 1}, "b": {"k": 2}, "c": [{"k": 3}, {"k": 4}]}'))
        ->toHaveKeys(['a', 'b', 'c']);
});

it('keeps big integers as strings', function (): void {
    expect(StrictJson::decodeObject('{"n": 123456789012345678901234567890}'))->toBe(['n' => '123456789012345678901234567890']);
});

it('refuses what is not one JSON object', function (string $json): void {
    expect(fn (): array => StrictJson::decodeObject($json))->toThrow(JsonException::class);
})->with([
    'a list' => ['[1, 2]'],
    'an empty list' => ['[]'],
    'a string' => ['"text"'],
    'a number' => ['42'],
    'null' => ['null'],
    'malformed' => ['{"a": 1,}'],
    'html' => ['<html>login</html>'],
    'empty' => [''],
    'two documents' => ['{"a": 1}{"b": 2}'],
]);

it('refuses an object with the same key twice', function (string $json): void {
    expect(fn (): array => StrictJson::decodeObject($json))->toThrow(JsonException::class, 'an object has the same key twice');
})->with([
    'top level' => ['{"iss": "a", "iss": "b"}'],
    'nested' => ['{"a": {"k": 1, "k": 2}}'],
    'inside a list' => ['{"keys": [{"kid": "1", "kid": "2"}]}'],
    'escaped spelling' => ['{"iss": "a", "iss": "b"}'],
    'after a nested object' => ['{"a": {"x": 1}, "b": 2, "a": 3}'],
    'after a string value with a quote and comma' => ['{"a": "x\",\"a", "a": 2}'],
]);

it('does not treat string values as keys', function (): void {
    expect(StrictJson::decodeObject('{"a": "a", "b": ["a", "a"], "c": "{\"a\": 1, \"a\": 2}"}'))->toHaveCount(3);
});

it('refuses a document nested deeper than the limit', function (): void {
    $json = str_repeat('{"a":', 40).'1'.str_repeat('}', 40);

    expect(fn (): array => StrictJson::decodeObject($json))->toThrow(JsonException::class);
});
