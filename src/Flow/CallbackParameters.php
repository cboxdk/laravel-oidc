<?php

declare(strict_types=1);

namespace Cbox\Oidc\Flow;

use Cbox\Oidc\Exceptions\CallbackRejected;
use Illuminate\Http\Request;

/**
 * The parameters of the authorization response, read from the callback's
 * query (the default query response mode): code, state, iss and error.
 *
 * A parameter that is present must be one string: state[]=a, for example,
 * is refused rather than read.
 *
 * @internal
 */
final readonly class CallbackParameters
{
    public function __construct(
        public ?string $code,
        public ?string $state,
        public ?string $iss,
        public mixed $error,
    ) {}

    public static function fromRequest(Request $request, string $connection): self
    {
        $read = static function (string $name) use ($request, $connection): ?string {
            $value = $request->query($name);

            if ($value === null) {
                return null;
            }

            if (! is_string($value)) {
                throw CallbackRejected::invalid($connection, sprintf('carries %s in a form other than one string', $name));
            }

            return $value;
        };

        return new self($read('code'), $read('state'), $read('iss'), $request->query('error'));
    }
}
