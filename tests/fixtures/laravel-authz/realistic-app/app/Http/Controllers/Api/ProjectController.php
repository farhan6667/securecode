<?php
// Realistic sample (false positive check): membership guard on the parent, scopeBindings() on the route.

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Project;
use App\Models\Task;
use Illuminate\Http\Request;

class ProjectController extends Controller
{
    public function show(Request $request, Project $project)
    {
        abort_unless($project->members()->whereKey($request->user()->id)->exists(), 404);
        return $project->load('tasks');
    }

    // expect: laravel-idor-route-model-binding gate-drops
    public function task(Request $request, Project $project, Task $task)
    {
        abort_unless($project->members()->whereKey($request->user()->id)->exists(), 404);
        return $task;
    }
}
