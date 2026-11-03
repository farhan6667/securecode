<?php
// Test fixture: controllers whose authorization lives in routes/web.php or in a FormRequest.
// Semgrep alone reports every marked line ("expect: <rule id>"). The word after the rule id says what
// secgate.py's route context must do with it: "gate-keeps" or "gate-drops".

namespace App\Http\Controllers;

use App\Http\Requests\NoteOrderRequest;
use App\Http\Requests\UpdateOrderRequest;
use App\Models\File;
use App\Models\Invoice;
use App\Models\Order;
use App\Models\Photo;
use App\Models\Post;
use App\Models\Project;
use App\Models\Task;
use App\Models\Team;
use App\Models\User;

class RouteOrderController extends Controller
{
    // expect: laravel-idor-route-model-binding gate-drops
    public function adminShow(Order $order)
    {
        return $order;
    }

    // expect: laravel-idor-route-model-binding gate-drops
    public function invoice(Invoice $invoice)
    {
        return $invoice;
    }

    // expect: laravel-idor-route-model-binding gate-drops
    public function purge(Order $order)
    {
        $order->forceDelete();
        return back();
    }

    // expect: laravel-idor-route-model-binding gate-drops
    public function pdf(Order $order)
    {
        return $order->pdf();
    }

    // expect: laravel-idor-route-model-binding gate-keeps
    public function show(Order $order)
    {
        return $order;
    }

    // expect: laravel-idor-route-model-binding gate-drops
    public function update(UpdateOrderRequest $request, Order $order)
    {
        $order->update($request->validated());
        return $order;
    }

    // expect: laravel-idor-route-model-binding gate-keeps
    public function note(NoteOrderRequest $request, Order $order)
    {
        $order->update($request->validated());
        return $order;
    }

    // expect: laravel-idor-route-model-binding gate-keeps
    public function raw(Order $order)
    {
        return $order->getAttributes();
    }

    // expect: laravel-idor-route-model-binding gate-keeps
    public function twice(Order $order)
    {
        return $order;
    }

    // expect: laravel-idor-route-model-binding gate-keeps
    public function open(Order $order)
    {
        return $order;
    }

    // expect: laravel-idor-route-model-binding gate-keeps
    public function summary(Order $order)
    {
        return $order->total;
    }

    // Not routed anywhere: nothing to drop it.
    // expect: laravel-idor-route-model-binding gate-keeps
    public function unrouted(Order $order)
    {
        return $order;
    }
}

class TeamProjectController extends Controller
{
    // scopeBindings() and the parent is checked: the child is covered.
    public function show(
        Team $team,
        // expect: laravel-idor-route-model-binding gate-drops
        Project $project
    ) {
        abort_unless($team->users()->whereKey(auth()->id())->exists(), 403);
        return $project;
    }

    // scopeBindings() but nobody checks the parent: both stay.
    public function task(
        // expect: laravel-idor-route-model-binding gate-keeps
        Team $team,
        // expect: laravel-idor-route-model-binding gate-keeps
        Task $task
    ) {
        return $task;
    }

    // A custom key on the child ({post:slug}) scopes it to the parent, and the parent is the caller.
    public function post(
        User $user,
        // expect: laravel-idor-route-model-binding gate-drops
        Post $post
    ) {
        abort_unless($user->is(auth()->user()), 403);
        return $post;
    }

    // The parent is checked but the route is not scoped: any file id works.
    public function file(
        Team $team,
        // expect: laravel-idor-route-model-binding gate-keeps
        File $file
    ) {
        abort_unless($team->users()->whereKey(auth()->id())->exists(), 403);
        return $file;
    }
}

class PhotoController extends Controller
{
    // expect: laravel-idor-route-model-binding gate-drops
    public function show(Photo $photo)
    {
        return $photo;
    }

    // Not a resource method, so the resource route's middleware does not reach it.
    // expect: laravel-idor-route-model-binding gate-keeps
    public function download(Photo $photo)
    {
        return response()->download($photo->path);
    }
}
