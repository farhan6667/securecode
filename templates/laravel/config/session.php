<?php
// Secure session settings. Merge these values into your config/session.php.
// Cookies are Secure, HttpOnly and SameSite=lax by default, and the session payload is encrypted.
// For local development over plain http, set SESSION_SECURE_COOKIE=false in your local .env only.
// Never in staging or production.

use Illuminate\Support\Str;

return [

    'driver' => env('SESSION_DRIVER', 'database'),

    // Minutes of inactivity before the session ends. Shorten it for admin-heavy apps.
    'lifetime' => (int) env('SESSION_LIFETIME', 120),

    'expire_on_close' => env('SESSION_EXPIRE_ON_CLOSE', false),

    // Encrypt the session data at rest (database, Redis, files).
    'encrypt' => env('SESSION_ENCRYPT', true),

    'files' => storage_path('framework/sessions'),

    'connection' => env('SESSION_CONNECTION'),

    'table' => env('SESSION_TABLE', 'sessions'),

    'store' => env('SESSION_STORE'),

    'lottery' => [2, 100],

    'cookie' => env('SESSION_COOKIE', Str::slug(env('APP_NAME', 'laravel'), '_').'_session'),

    'path' => env('SESSION_PATH', '/'),

    // Leave empty unless you really share the session across subdomains.
    'domain' => env('SESSION_DOMAIN'),

    // Only send the cookie over https.
    'secure' => env('SESSION_SECURE_COOKIE', true),

    // JavaScript cannot read the cookie.
    'http_only' => env('SESSION_HTTP_ONLY', true),

    // "lax" blocks the cookie on cross-site POSTs. Use "strict" if no external links need a login.
    'same_site' => env('SESSION_SAME_SITE', 'lax'),

    'partitioned' => env('SESSION_PARTITIONED_COOKIE', false),

];
