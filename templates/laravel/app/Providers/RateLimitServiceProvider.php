<?php
// Rate limits for login, OTP and password reset. The login limiter has three counters: one per
// account and IP pair, one per IP (one address cannot try many accounts), and one per account alone
// (many addresses cannot hammer one account). The per-account counter also lets an attacker lock a
// real user out of password login for up to an hour, so keep a password reset or passkey route that
// still works, and alert on accounts that hit it.
// The numbers are example values: set them to what your users really need.
// Laravel 11: put the boot() body in AppServiceProvider::boot(), or register this provider in
// bootstrap/providers.php. Laravel 10 and older: put it in RouteServiceProvider::boot().
// Use the limiters in routes with ->middleware('throttle:login') (see ../../routes/auth-throttle.php).

namespace App\Providers;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Str;

class RateLimitServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        RateLimiter::for('login', function (Request $request) {
            $account = Str::lower((string) $request->input('email'));

            return [
                Limit::perMinute(5)->by('login:'.$account.'|'.$request->ip()),
                Limit::perMinute(20)->by('login-ip:'.$request->ip()),
                Limit::perHour(10)->by('login-account:'.$account),
            ];
        });

        RateLimiter::for('otp', function (Request $request) {
            $who = $request->user()?->getAuthIdentifier() ?? $request->ip();

            return [
                Limit::perMinute(3)->by('otp:'.$who),
                Limit::perHour(10)->by('otp-hour:'.$who),
            ];
        });

        RateLimiter::for('password-reset', function (Request $request) {
            $account = Str::lower((string) $request->input('email'));

            return [
                Limit::perMinute(3)->by('reset:'.$account),
                Limit::perHour(10)->by('reset-ip:'.$request->ip()),
            ];
        });
    }
}
