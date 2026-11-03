<?php
// Security headers on every kind of page: the home page, the login page and an admin route.
// Pentests check the login and admin pages, so a header set on one page only fails the retest.
// The admin route may redirect a guest to /login; the headers must be on that redirect too.

use App\Models\User;

dataset('pages', ['/', '/login', '/admin']);

function assertSecurityHeaders($response): void
{
    $response->assertHeader('X-Content-Type-Options', 'nosniff');
    $response->assertHeader('Referrer-Policy');
    $response->assertHeader('Permissions-Policy');

    $csp = (string) $response->headers->get('Content-Security-Policy');
    expect($csp)->not->toBe('');
    expect($csp)->not->toContain("'unsafe-eval'");

    $framing = $response->headers->get('X-Frame-Options') ?? '';
    expect(str_contains($csp, 'frame-ancestors') || in_array(strtoupper($framing), ['DENY', 'SAMEORIGIN'], true))->toBeTrue();
}

it('sends security headers to guests', function (string $path) {
    assertSecurityHeaders($this->get($path));
})->with('pages');

it('sends security headers to a signed-in admin', function () {
    // Change this to however your app marks an admin (a role column, a permission package, ...).
    $admin = User::factory()->create(['is_admin' => true]);

    assertSecurityHeaders($this->actingAs($admin)->get('/admin'));
});

it('sends HSTS over https only', function () {
    $this->get('https://localhost/')->assertHeader('Strict-Transport-Security');
    $this->get('http://localhost/')->assertHeaderMissing('Strict-Transport-Security');
});
