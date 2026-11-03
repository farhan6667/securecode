# Laravel security scaffolds

Small, commented starting points for the fixes pentests ask for most on Laravel apps. Copy the file
to the same path in your project, read its header comment, and adapt it. Paths below are relative
to your project root.

| File | What it fixes |
|---|---|
| `app/Http/Middleware/SecurityHeaders.php` | Missing CSP, X-Frame-Options / frame-ancestors, nosniff, Referrer-Policy, Permissions-Policy, and HSTS (sent over https only). |
| `config/session.php` | Session cookies without Secure, HttpOnly or SameSite; unencrypted session data. |
| `app/Providers/RateLimitServiceProvider.php` and `routes/auth-throttle.php` | No rate limit on login, OTP and password reset. |
| `app/Http/Requests/StoreAvatarRequest.php` | Uploads checked by name only, no size limit, PHP code hidden in an image. |
| `app/Http/Middleware/VerifyWebhookSignature.php` | Unauthenticated webhooks: HMAC check with `hash_equals` and a timestamp window. |

## Register the middleware

The headers middleware must run on every response, the login page and admin routes included. A
header set on one page only fails the retest.

**Laravel 11 and newer** (`bootstrap/app.php`):

```php
use App\Http\Middleware\SecurityHeaders;
use App\Http\Middleware\VerifyWebhookSignature;
use Illuminate\Foundation\Configuration\Middleware;

->withMiddleware(function (Middleware $middleware) {
    $middleware->append(SecurityHeaders::class);
    $middleware->alias([
        'webhook.signed' => VerifyWebhookSignature::class,
    ]);
})
```

**Laravel 10 and older** (`app/Http/Kernel.php`):

```php
protected $middleware = [
    // ... the existing global middleware ...
    \App\Http\Middleware\SecurityHeaders::class,
];

// Laravel 10: $middlewareAliases. Laravel 9 and older: $routeMiddleware.
protected $middlewareAliases = [
    // ... the existing aliases ...
    'webhook.signed' => \App\Http\Middleware\VerifyWebhookSignature::class,
];
```

Then protect the webhook route and keep it out of CSRF checks (it is signed instead):

```php
Route::post('/webhooks/payments', PaymentWebhookController::class)->middleware('webhook.signed');
```

Laravel 11: `$middleware->validateCsrfTokens(except: ['webhooks/*']);` in `bootstrap/app.php`.
Laravel 10 and older: add `'webhooks/*'` to `$except` in `app/Http/Middleware/VerifyCsrfToken.php`.

## Register the rate limits

Laravel 11: add `App\Providers\RateLimitServiceProvider::class` to `bootstrap/providers.php`, or move
its `boot()` body into `AppServiceProvider::boot()`. Laravel 10 and older: move it into
`RouteServiceProvider::boot()`. Then use `throttle:login`, `throttle:otp` and
`throttle:password-reset` on the routes, as in `routes/auth-throttle.php`.

## Check it

The tests in `../security-tests/laravel/` cover these scaffolds: `SecurityHeadersTest.php` for the
headers and `UploadRefusesScriptsTest.php` for uploads. Run them after you copy the files.
