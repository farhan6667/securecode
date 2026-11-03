<?php

use App\Http\Controllers\Api\TaskController;
use App\Http\Controllers\Api\ProjectController;
use Illuminate\Support\Facades\Route;

Route::middleware('auth:sanctum')->group(function () {
    Route::apiResource('tasks', TaskController::class);
    Route::get('/projects/{project}', [ProjectController::class, 'show']);
    Route::get('/projects/{project}/tasks/{task}', [ProjectController::class, 'task'])->scopeBindings();
});
