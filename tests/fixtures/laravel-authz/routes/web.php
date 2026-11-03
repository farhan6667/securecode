<?php
// Test fixture for semgrep/laravel-authz.yml: web route groups.

use App\Http\Controllers\Admin\UserController;
use App\Http\Controllers\BlogController;
use App\Http\Controllers\DashboardController;
use Illuminate\Support\Facades\Route;

// Must be reported: a group for signed-in areas without auth middleware.
// expect: laravel-web-group-without-auth
Route::prefix('admin')->name('admin.')->group(function () {
    Route::get('/users', [UserController::class, 'index']);
    Route::delete('/users/{user}', [UserController::class, 'destroy']);
});

// expect: laravel-web-group-without-auth
Route::group(['prefix' => 'dashboard'], function () {
    Route::get('/', [DashboardController::class, 'index']);
});

// Must not be reported.
Route::middleware(['auth', 'can:admin'])->prefix('admin')->group(function () {
    Route::get('/settings', [UserController::class, 'settings']);
});

Route::prefix('account')->middleware('auth')->group(function () {
    Route::get('/', [DashboardController::class, 'account']);
});

Route::prefix('blog')->group(function () {
    Route::get('/', [BlogController::class, 'index']);
});

Route::get('/', fn () => view('welcome'));
