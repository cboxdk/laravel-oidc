<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tests\Fixtures;

use Cbox\Oidc\Contracts\OidcClient;
use Cbox\Oidc\Exceptions\AuthorizationDenied;
use Cbox\Oidc\Exceptions\OidcException;
use Cbox\Oidc\Facades\Oidc;
use Cbox\Oidc\Flow\AuthorizationOptions;
use Cbox\Oidc\Flow\Prompt;
use Cbox\Oidc\Logout\LogoutOptions;
use Cbox\Oidc\Testing\OidcFake;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Routing\Router;

/**
 * An application's use of the public API, as a consumer writes it. PHPStan
 * analyses this file at level max, so a wrong @method on the facade or a
 * wrong type on the fake fails the build; tests/Feature/Testing runs it.
 */
final class ConsumerApp
{
    public static function routes(Router $router): void
    {
        $router->group(['middleware' => 'web'], static function (Router $router): void {
            $router->get('/consumer/login', static fn (): RedirectResponse => Oidc::redirect(options: new AuthorizationOptions(prompt: Prompt::SelectAccount)));

            $router->get('/consumer/callback', static function (OidcClient $oidc): JsonResponse|RedirectResponse {
                try {
                    $result = $oidc->callback();
                } catch (AuthorizationDenied $denied) {
                    return new RedirectResponse('/?denied='.$denied->error());
                } catch (OidcException $exception) {
                    return new RedirectResponse('/?failed='.$exception->errorCode()->value);
                }

                session(['oidc.claims' => $result->claims, 'oidc.refresh' => $result->tokens->refreshToken, 'oidc.id_token' => $result->tokens->idToken]);

                return new JsonResponse(['subject' => $result->claims->subject, 'groups' => $result->claims->groups]);
            });

            $router->post('/consumer/logout', static function (): RedirectResponse {
                $idToken = session('oidc.id_token');

                return Oidc::connection()->logout(new LogoutOptions(idTokenHint: is_string($idToken) ? $idToken : null), '/goodbye');
            });
        });
    }

    /**
     * What a consumer's test does with the fake.
     */
    public static function arrange(OidcFake $fake): OidcFake
    {
        return $fake->signIn('ada', ['groups' => ['staff']])->denySignIn('access_denied');
    }
}
