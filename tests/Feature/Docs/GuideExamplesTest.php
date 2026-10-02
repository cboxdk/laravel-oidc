<?php

declare(strict_types=1);

use App\Http\Controllers\OidcLoginController;
use App\Models\User;
use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Contracts\HttpClient;
use Cbox\Oidc\Contracts\OidcClient;
use Cbox\Oidc\Contracts\TransactionStore;
use Cbox\Oidc\Discovery\MetadataRepository;
use Cbox\Oidc\Facades\Oidc;
use Cbox\Oidc\Flow\AuthorizationTransaction;
use Cbox\Oidc\Keys\KeySetRepository;
use Cbox\Oidc\OidcManager;
use Cbox\Oidc\Tests\Support\ClientKeys;
use Cbox\Oidc\Tests\Support\ConnectionFixtures;
use Cbox\Oidc\Tests\Support\DocExamples;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\ServiceProvider;

/**
 * Runs the code samples of the quickstart, the testing guide, the facade
 * page, the connection check and the smaller samples of the core-concept and
 * extension-point pages.
 */
function runDocTests(string $name): void
{
    $tests = DocExamples::tests($name);
    expect($tests)->not->toBeEmpty();

    foreach ($tests as $description => $test) {
        // Each documented test starts from a fresh fake, as in its own test.
        Oidc::clearResolvedInstance(OidcClient::class);
        app()->forgetInstance(OidcClient::class);
        app()->singleton(OidcClient::class, OidcManager::class);
        session()->flush();

        try {
            Closure::bind($test, test(), test()::class)();
        } catch (Throwable $exception) {
            throw new RuntimeException(sprintf('The documented test "%s" of example %s failed: %s', $description, $name, $exception->getMessage()), 0, $exception);
        }
    }
}

describe('the quickstart', function (): void {
    beforeEach(function (): void {
        config(['database.default' => 'sqlite', 'database.connections.sqlite.database' => ':memory:']);

        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->timestamp('email_verified_at')->nullable();
            $table->string('password');
            $table->rememberToken();
            $table->timestamps();
        });

        $migration = DocExamples::run('setup-migration');
        expect($migration)->toBeInstanceOf(Migration::class);
        $migration->up();

        if (! class_exists('App\Models\User')) {
            DocExamples::run('setup-model');
        }

        Route::middleware('web')->group(fn (): mixed => DocExamples::run('setup-routes'));
    });

    it('signs a person in through the setup routes, against the real provider', function (): void {
        $provider = new FakeProvider()->install();

        $login = $this->get('/login');
        $query = $provider->approve((string) $login->headers->get('Location'), ['sub' => 'ada', 'email' => 'ada@example.com', 'name' => 'Ada']);

        $this->withCookie((string) config('session.cookie'), (string) $login->getCookie((string) config('session.cookie'))?->getValue())
            ->get('/oidc/callback?'.http_build_query($query))
            ->assertRedirect('/');

        $this->assertAuthenticated();
        expect(User::query()->sole()->only(['oidc_issuer', 'oidc_subject', 'name', 'email', 'password']))
            ->toBe(['oidc_issuer' => FakeProvider::ISSUER, 'oidc_subject' => 'ada', 'name' => 'Ada', 'email' => 'ada@example.com', 'password' => null]);
    });

    it('updates the same user at the next sign-in', function (): void {
        Oidc::fake()->signIn('ada', ['email' => 'ada@example.com'])->signIn('ada', ['email' => 'ada@example.org']);

        $this->get('/oidc/callback')->assertRedirect('/');
        $this->get('/oidc/callback')->assertRedirect('/');

        expect(User::query()->sole()->email)->toBe('ada@example.org');
    });

    it('runs the documented test', function (): void {
        runDocTests('setup-test');
    });

    it('rolls the migration back', function (): void {
        DocExamples::run('setup-migration')->down();

        expect(Schema::hasColumn('users', 'oidc_issuer'))->toBeFalse();
    });
});

describe('the testing guide', function (): void {
    beforeEach(function (): void {
        foreach (['login-routes', 'logout-route', 'backchannel-logout'] as $routes) {
            DocExamples::run($routes);
        }
    });

    it('runs the documented tests', function (string $name): void {
        runDocTests($name);
    })->with(['testing-sign-in', 'testing-failures', 'testing-refresh', 'testing-logout', 'testing-backchannel']);
});

it('answers the two routes of the overview', function (): void {
    Route::middleware('web')->group(fn (): mixed => DocExamples::run('index-routes'));
    Oidc::fake()->signIn('ada');

    $this->get('/login')->assertRedirect();
    $this->get('/oidc/callback')->assertOk()->assertContent('ada');
});

it('routes several connections through the documented controller', function (): void {
    DocExamples::run('facade-controller');
    Route::middleware('web')->get('/oidc/{connection}/login', [OidcLoginController::class, 'redirect']);
    Route::middleware('web')->get('/oidc/{connection}/callback', [OidcLoginController::class, 'callback']);

    $oidc = Oidc::fake()->signIn('person', connection: 'workspace');

    $this->get('/oidc/workspace/login')->assertRedirect();
    $this->get('/oidc/workspace/callback')->assertRedirect('/')->assertSessionHas('status', 'Signed in through workspace.');

    $oidc->assertRedirected('workspace');
    $oidc->assertSignedIn('person', 'workspace');
});

it('sends the documented authorization options', function (): void {
    new FakeProvider()->install();

    $redirect = DocExamples::run('authorization-options');
    expect($redirect)->toBeInstanceOf(RedirectResponse::class);
    parse_str((string) parse_url($redirect->getTargetUrl(), PHP_URL_QUERY), $query);

    expect($query)->toMatchArray([
        'prompt' => 'login',
        'max_age' => '0',
        'login_hint' => 'ada@example.com',
        'scope' => 'openid profile email offline_access',
        'acr_values' => 'urn:example:mfa',
        'domain_hint' => 'example.com',
    ]);
});

it('prints the documented oidc:check output', function (): void {
    $this->fakeSsrfDns(['login.example.com' => ['93.184.216.34']]);
    config(['oidc.connections.main' => ConnectionFixtures::minimal([
        'issuer' => 'https://login.example.com',
        'client_id' => 'your-client-id',
        'client_secret' => 'your-client-secret',
        'redirect_uri' => 'https://app.example.com/oidc/callback',
    ])]);

    $provider = new FakeProvider('https://login.example.com');
    $provider->clients = ['your-client-id' => ['secret' => 'your-client-secret']];
    $provider->keys = [FakeProvider::rsaKey('2026-09'), FakeProvider::rsaKey('2026-10')];
    $provider->discovery['id_token_signing_alg_values_supported'] = ['RS256'];
    unset($provider->discovery['revocation_endpoint'], $provider->discovery['backchannel_logout_supported']);
    $provider->install();

    Artisan::call('oidc:check');
    $printed = implode("\n", array_map(rtrim(...), explode("\n", trim(Artisan::output(), "\n"))));

    expect($printed)->toBe(rtrim(DocExamples::code('oidc-check-output')));
});

it('drops the cached documents as documented', function (): void {
    $provider = new FakeProvider()->install();
    $connection = resolve(OidcConfig::class)->connection('main');
    resolve(KeySetRepository::class)->for($connection, resolve(MetadataRepository::class)->for($connection));

    DocExamples::run('forget-cache');
    resolve(KeySetRepository::class)->for($connection, resolve(MetadataRepository::class)->for($connection));

    expect($provider->discoveryRequests)->toBe(2)
        ->and($provider->jwksRequests)->toBe(2);
});

it('binds the documented HTTP client and transaction store', function (): void {
    $provider = new class(app()) extends ServiceProvider {};

    DocExamples::run('http-client-binding', bind: $provider);
    DocExamples::run('transaction-store-binding', bind: $provider);

    expect(app()->getBindings()[HttpClient::class]['shared'])->toBeTrue()
        ->and(app()->getBindings()[TransactionStore::class]['shared'])->toBeTrue()
        ->and(resolve(TransactionStore::class))->toBeInstanceOf('MyTransactionStore');
});

it('parses every documented connection fragment', function (string $location, string $code): void {
    $key = storage_path('oidc/client.pem');
    @mkdir(dirname($key), 0700, true);
    file_put_contents($key, ClientKeys::rsa());
    putenv('OIDC_CLIENT_KEY_ID=client-key-1');
    putenv('OIDC_CLIENT_CERT_THUMBPRINT=1GP6s9W0mQyqVkaHRo5V0nPPGrtnvfFbDLbuFk4Eszc');

    try {
        $fragment = DocExamples::runCode("<?php\n\nreturn [\n".$code."];\n");
        expect($fragment)->toBeArray();

        $config = OidcConfig::fromArray(['connections' => ['main' => array_replace(ConnectionFixtures::minimal(), $fragment)]]);
    } finally {
        unlink($key);
        putenv('OIDC_CLIENT_KEY_ID');
        putenv('OIDC_CLIENT_CERT_THUMBPRINT');
    }

    expect($config->connection()->name)->toBe('main');
})->with(fn (): array => array_map(
    static fn (string $location, string $code): array => [$location, $code],
    array_keys(DocExamples::all('config-fragment')),
    DocExamples::all('config-fragment'),
));

/**
 * The transaction store the extension-point page binds.
 */
final class MyTransactionStore implements TransactionStore
{
    public function put(AuthorizationTransaction $transaction): void {}

    public function pull(string $state): ?AuthorizationTransaction
    {
        return null;
    }
}
