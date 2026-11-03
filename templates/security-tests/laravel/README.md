# Laravel security tests (Pest)

Short feature tests for the findings pentests report most on Laravel apps. They are examples: copy
them, then change the models, routes and field names to your own. A test you did not adapt proves
nothing.

| File | What it proves |
|---|---|
| `CrossUserAccessTest.php` | User B gets 403 or 404 on user A's order for GET, PUT, PATCH, DELETE and export, and the order is unchanged. |
| `XssRoundTripTest.php` | A saved script payload comes back escaped. |
| `UploadRefusesScriptsTest.php` | `shell.php`, a double extension and PHP content named `.jpg` are refused with 422, and nothing is stored. |
| `ExposedPathsTest.php` | `/.env`, `/.git/config`, `/telescope`, `/horizon` and similar paths return 404. |
| `SecurityHeadersTest.php` | CSP, framing, nosniff, Referrer-Policy and Permissions-Policy on `/`, `/login` and an admin route; HSTS on https only. |

## Copy them

From your Laravel project root (Pest is the default test runner since Laravel 11):

```
mkdir -p tests/Security
cp "<APP>/templates/security-tests/laravel/"*Test.php tests/Security/
```

`<APP>` is the SecureCode install folder (Windows `%LOCALAPPDATA%\OrgAISecureAppSec`).

Let Pest boot Laravel for the new folder. In `tests/Pest.php`:

```php
pest()->extend(Tests\TestCase::class)
    ->use(Illuminate\Foundation\Testing\RefreshDatabase::class)
    ->in('Feature', 'Security');
```

On Pest 2 the same line is `uses(Tests\TestCase::class, RefreshDatabase::class)->in('Feature', 'Security');`.
Then add the folder to `phpunit.xml`:

```xml
<testsuite name="Security">
    <directory>tests/Security</directory>
</testsuite>
```

Run them:

```
php artisan test tests/Security
```

## Adapt them

- One row in the `order routes` dataset per row of `.security/authz-matrix.md`. A row without a
  passing test is open.
- Your models need factories (`Order::factory()->for($user)`).
- On PHPUnit instead of Pest, keep the same requests and assertions inside `test_*` methods of a
  class that extends `Tests\TestCase`.

## Also check the live server

Feature tests only see what Laravel routes. The web server answers `/.env` and `/.git` before
Laravel does, so check staging too:

```
curl -s -o /dev/null -w "%{http_code}\n" https://staging.example.com/.env
curl -s -o /dev/null -w "%{http_code}\n" https://staging.example.com/.git/config
```

Both should print 404 (403 is acceptable for dotfiles, but 200 is a finding).
