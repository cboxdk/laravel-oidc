<?php

declare(strict_types=1);

use Cbox\Oidc\Facades\Oidc;
use Cbox\Oidc\Flow\AuthorizationOptions;
use Cbox\Oidc\Flow\Prompt;
use Cbox\Oidc\Logout\LogoutOptions;
use Cbox\Oidc\Tests\Fixtures\ConsumerApp;
use Illuminate\Routing\Router;

/**
 * Runs the consumer fixture's routes against Oidc::fake(), as an
 * application's own feature tests would.
 */
beforeEach(function (): void {
    ConsumerApp::routes(resolve(Router::class));
    $this->fake = ConsumerApp::arrange(Oidc::fake());
});

it('signs in, is denied, and logs out through the routes of an application', function (): void {
    $this->get('/consumer/login')->assertRedirect();
    $this->fake->assertRedirected('main', fn (AuthorizationOptions $options): bool => $options->prompts === [Prompt::SelectAccount]);

    $this->get('/consumer/callback')->assertOk()->assertExactJson(['subject' => 'ada', 'groups' => ['staff']]);
    $this->get('/consumer/callback')->assertRedirect('/?denied=access_denied');

    $this->fake->assertSignedIn('ada');
    $this->fake->assertNoPendingSignIns();

    $this->post('/consumer/logout')->assertRedirect('/goodbye');
    $this->fake->assertLoggedOut(callback: fn (LogoutOptions $options): bool => $options->idTokenHint === $this->fake->signIns()[0]->tokens->idToken);
});
