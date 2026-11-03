<?php
// Test fixture for semgrep/laravel-authz.yml: API routes.

use App\Http\Controllers\AuthController;
use App\Http\Controllers\OrderController;
use App\Http\Controllers\ReportController;
use Illuminate\Support\Facades\Route;

// Must be reported: no auth middleware anywhere.
// expect: laravel-api-route-without-auth
Route::get('/orders/{order}', [OrderController::class, 'show']);
// expect: laravel-api-route-without-auth
Route::delete('/orders/{order}', [OrderController::class, 'destroy']);
// expect: laravel-api-route-without-auth
Route::apiResource('reports', ReportController::class);
// expect: laravel-api-route-without-auth
Route::get('/admin/export', [ReportController::class, 'export'])->middleware('throttle:10,1');

Route::prefix('v2')->group(function () {
    // expect: laravel-api-route-without-auth
    Route::put('/orders/{order}', [OrderController::class, 'update']);
});

// Must be reported: the URI only contains a word from the public list, not a whole public endpoint.
// expect: laravel-api-route-without-auth
Route::get('/shipping-addresses/{id}', [OrderController::class, 'address']);
// expect: laravel-api-route-without-auth
Route::get('/users/{user}/password-history', [AuthController::class, 'history']);
// expect: laravel-api-route-without-auth
Route::post('/orders/{o}/reset-status', [OrderController::class, 'resetStatus']);
// expect: laravel-api-route-without-auth
Route::post('/orders/{o}/verify-payment', [OrderController::class, 'verifyPayment']);
// expect: laravel-api-route-without-auth
Route::get('/mapping/{id}', [ReportController::class, 'mapping']);
// expect: laravel-api-route-without-auth
Route::get('/login-history', [AuthController::class, 'loginHistory']);

// Must not be reported: real public sign-in and health endpoints.
Route::post('/login', [AuthController::class, 'login'])->middleware('throttle:5,1');
Route::post('/register', [AuthController::class, 'register']);
Route::post('/forgot-password', [AuthController::class, 'forgot']);
Route::post('/password/forgot', [AuthController::class, 'forgot']);
Route::post('/password/reset', [AuthController::class, 'reset']);
Route::get('/password/reset/{token}', [AuthController::class, 'resetForm']);
Route::get('/email/verify/{id}/{hash}', [AuthController::class, 'verify']);
Route::post('/v1/auth/login', [AuthController::class, 'login']);
Route::get('/health', fn () => ['ok' => true]);
Route::get('/ping', fn () => 'pong');
Route::get('up', fn () => 'ok');

Route::get('/me', [AuthController::class, 'me'])->middleware('auth:sanctum');
Route::get('/me/orders', [OrderController::class, 'index'])->middleware(['throttle:60,1', 'auth:sanctum']);

Route::middleware('auth:sanctum')->group(function () {
    Route::get('/orders', [OrderController::class, 'index']);
    Route::patch('/orders/{order}', [OrderController::class, 'update']);
});

Route::middleware(['auth:sanctum', 'verified'])->prefix('v1')->group(function () {
    Route::apiResource('invoices', ReportController::class);
});

Route::group(['middleware' => 'auth:api', 'prefix' => 'legacy'], function () {
    Route::get('/orders', [OrderController::class, 'index']);
});

Route::get('/catalogue', [OrderController::class, 'catalogue']); // securecode: public-object
