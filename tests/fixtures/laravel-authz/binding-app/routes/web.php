<?php
// Test fixture for the route context that secgate.py adds to laravel-idor-route-model-binding.
// Semgrep reports every controller method in ../app; laravel_binding_context() must drop exactly the
// ones whose route or FormRequest carries the check (see the markers in the controller file).

use App\Http\Controllers\PhotoController;
use App\Http\Controllers\RouteOrderController;
use App\Http\Controllers\TeamProjectController;
use App\Models\Order;
use Illuminate\Support\Facades\Route;

Route::middleware('auth')->group(function () {
    // Policy on the route.
    Route::get('/orders/{order}/admin', [RouteOrderController::class, 'adminShow'])->can('view', 'order');

    // Admin-only group.
    Route::middleware(['auth', 'can:admin'])->group(function () {
        Route::get('/invoices/{invoice}', [RouteOrderController::class, 'invoice']);
    });
    Route::group(['middleware' => ['role:super-admin']], function () {
        Route::delete('/orders/{order}/purge', [RouteOrderController::class, 'purge']);
    });

    // A controller group with an admin role on the route.
    Route::controller(RouteOrderController::class)->group(function () {
        Route::get('/orders/{order}/pdf', 'pdf')->middleware('role:admin');
    });

    // Plain auth only: signed in is not the same as allowed.
    Route::get('/orders/{order}', [RouteOrderController::class, 'show']);

    // The check lives in the FormRequest.
    Route::put('/orders/{order}', [RouteOrderController::class, 'update']);
    Route::patch('/orders/{order}/note', [RouteOrderController::class, 'note']);

    // A commented-out ->can() does not count.
    // Route::get('/orders/{order}/raw', [RouteOrderController::class, 'raw'])->can('view', 'order');
    Route::get('/orders/{order}/raw', [RouteOrderController::class, 'raw']);

    // Protected on one route, open on another: still reported.
    Route::get('/orders/{order}/twice', [RouteOrderController::class, 'twice'])->can('view', 'order');
    Route::get('/o/{order}/twice', [RouteOrderController::class, 'twice']);

    // A class-level ability checks no row.
    Route::get('/orders/{order}/summary', [RouteOrderController::class, 'summary'])->can('viewAny', Order::class);
    Route::get('/o/{order}/summary', [RouteOrderController::class, 'summary'])->middleware('can:viewAny,App\Models\Order');

    // withoutMiddleware is not middleware.
    Route::get('/orders/{order}/open', [RouteOrderController::class, 'open'])->withoutMiddleware('can:view,order');

    // Nested resources.
    Route::scopeBindings()->group(function () {
        Route::get('/teams/{team}/projects/{project}', [TeamProjectController::class, 'show']);
        Route::get('/teams/{team}/tasks/{task}', [TeamProjectController::class, 'task']);
    });
    Route::get('/users/{user}/posts/{post:slug}', [TeamProjectController::class, 'post']);
    Route::get('/teams/{team}/files/{file}', [TeamProjectController::class, 'file']);
});

Route::resource('photos', PhotoController::class)->middleware('can:manage-photos');
