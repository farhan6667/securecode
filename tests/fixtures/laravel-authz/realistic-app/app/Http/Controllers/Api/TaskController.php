<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Resources\TaskResource;
use App\Models\Task;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

class TaskController extends Controller
{
    public function index(Request $request)
    {
        return TaskResource::collection($request->user()->tasks()->paginate());
    }

    public function store(Request $request)
    {
        $data = $request->validate(['title' => 'required|string|max:200']);
        return new TaskResource($request->user()->tasks()->create($data));
    }

    public function show(Task $task)
    {
        Gate::authorize('view', $task);
        return new TaskResource($task);
    }

    public function update(Request $request, Task $task)
    {
        if ($request->user()->cannot('update', $task)) {
            abort(403);
        }
        $task->update($request->validate(['title' => 'sometimes|string|max:200', 'done' => 'boolean']));
        return new TaskResource($task);
    }

    public function destroy(Request $request, Task $task)
    {
        abort_if($task->user_id !== $request->user()->id, 403);
        $task->delete();
        return response()->noContent();
    }
}
