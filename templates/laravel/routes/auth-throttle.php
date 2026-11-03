<?php
// Throttle examples for the routes attackers brute force: login, OTP and password reset.
// Copy the middleware lines into your routes/web.php (or routes/auth.php). The limiters are
// defined in ../app/Providers/RateLimitServiceProvider.php. Controller names are placeholders.
// Laravel Fortify users: set 'limiters' => ['login' => 'login', 'two-factor' => 'otp'] in
// config/fortify.php instead of adding these routes.
// The OTP itself must also be single use and expire, which throttling does not replace.

use App\Http\Controllers\Auth\AuthenticatedSessionController;
use App\Http\Controllers\Auth\NewPasswordController;
use App\Http\Controllers\Auth\OtpController;
use App\Http\Controllers\Auth\PasswordResetLinkController;
use Illuminate\Support\Facades\Route;

Route::middleware('guest')->group(function () {
    Route::post('/login', [AuthenticatedSessionController::class, 'store'])
        ->middleware('throttle:login');

    Route::post('/forgot-password', [PasswordResetLinkController::class, 'store'])
        ->middleware('throttle:password-reset')
        ->name('password.email');

    Route::post('/reset-password', [NewPasswordController::class, 'store'])
        ->middleware('throttle:password-reset')
        ->name('password.store');
});

Route::middleware('auth')->group(function () {
    Route::post('/otp/send', [OtpController::class, 'send'])->middleware('throttle:otp');
    Route::post('/otp/verify', [OtpController::class, 'verify'])->middleware('throttle:otp');
});
