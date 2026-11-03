<?php
// What this test proves, and what it does not: it only shows that the Laravel app does not route
// these paths. It runs inside the framework and never reaches the web server, and Nginx, Apache or
// Caddy can still serve /.env, /.git/config or a stray phpinfo.php straight from disk. A pass here
// is not enough: also check the web server config with a real request against staging (the curl
// check in README.md).
//
// Sensitive files and debug panels must not exist outside local development.
// A 403 from /telescope or /horizon still tells an attacker the panel is there: register those
// service providers only when app()->environment('local'), so the route does not exist at all.

dataset('hidden paths', [
    '/.env',
    '/.env.backup',
    '/.git/config',
    '/telescope',
    '/horizon',
    '/_ignition/health-check',
    '/phpinfo.php',
    '/composer.json',
    '/storage/logs/laravel.log',
]);

it('returns 404 for sensitive paths', function (string $path) {
    $this->get($path)->assertNotFound();
})->with('hidden paths');

it('does not show a stack trace for an unknown id', function () {
    config(['app.debug' => false]);

    $this->get('/this-route-does-not-exist-'.uniqid())
        ->assertNotFound()
        ->assertDontSee('vendor/laravel', false)
        ->assertDontSee('Stack trace', false);
});
