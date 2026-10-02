<?php

declare(strict_types=1);

namespace Cbox\Oidc\Support;

use JsonException;

/**
 * Decodes a JSON object and refuses what json_decode() lets through
 * silently: a document that is not an object, and an object with the same
 * key twice. json_decode() keeps the last of two equal keys, while another
 * parser may keep the first, so a document with duplicates can mean different
 * things to the provider and to us.
 *
 * @internal
 */
final class StrictJson
{
    public const int MAX_DEPTH = 32;

    /**
     * @param  int<1, max>  $depth
     * @return array<array-key, mixed>
     *
     * @throws JsonException
     */
    public static function decodeObject(string $json, int $depth = self::MAX_DEPTH): array
    {
        $value = json_decode($json, true, $depth, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);

        if (! is_array($value) || ltrim($json, " \t\n\r")[0] !== '{') {
            throw new JsonException('the document is not a JSON object');
        }

        self::assertUniqueKeys($json);

        return $value;
    }

    /**
     * Walks the (already valid) JSON text and checks the keys of every object.
     * Keys are compared after decoding, so "a" and "a" are the same key.
     *
     * @throws JsonException
     */
    private static function assertUniqueKeys(string $json): void
    {
        /** @var list<array{object: bool, keys: array<string, true>, expectsKey: bool}> $stack */
        $stack = [];
        $length = strlen($json);

        for ($i = 0; $i < $length; $i++) {
            $char = $json[$i];

            if ($char === '"') {
                $end = self::stringEnd($json, $i);
                $top = array_key_last($stack);

                if ($top !== null && $stack[$top]['object'] && $stack[$top]['expectsKey']) {
                    $key = json_decode(substr($json, $i, $end - $i + 1), false, 1, JSON_THROW_ON_ERROR);
                    $key = is_string($key) ? $key : '';

                    if (isset($stack[$top]['keys'][$key])) {
                        throw new JsonException('an object has the same key twice');
                    }

                    $stack[$top]['keys'][$key] = true;
                    $stack[$top]['expectsKey'] = false;
                }

                $i = $end;

                continue;
            }

            if ($char === '{' || $char === '[') {
                $stack[] = ['object' => $char === '{', 'keys' => [], 'expectsKey' => $char === '{'];
            } elseif ($char === '}' || $char === ']') {
                array_pop($stack);
            } elseif ($char === ',') {
                $top = array_key_last($stack);

                if ($top !== null && $stack[$top]['object']) {
                    $stack[$top]['expectsKey'] = true;
                }
            }
        }
    }

    /**
     * The offset of the quote that closes the string opening at $start.
     */
    private static function stringEnd(string $json, int $start): int
    {
        $length = strlen($json);

        for ($i = $start + 1; $i < $length; $i++) {
            if ($json[$i] === '\\') {
                $i++;
            } elseif ($json[$i] === '"') {
                return $i;
            }
        }

        return $length - 1;
    }
}
