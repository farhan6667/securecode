<?php
// Test fixture for semgrep/laravel-authz.yml: IDOR through route model binding (benchmark L18).
// Every method below takes a model bound from the route and never checks who may use it.
// A line marked "expect: <rule id>" means the next line must produce that finding.

namespace App\Http\Controllers;

use App\Models\Order;
use App\Models\Invoice as Bill;
use App\Models\Team;
use App\Models\Project;
use Domain\Shop\Models\Cart;
use App\Services\PdfService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Log;

class BindingIdorController extends Controller
{
    // Route::get('/orders/{order}', ...): returns anyone's order.
    // expect: laravel-idor-route-model-binding
    public function show(Order $order)
    {
        return $order;
    }

    // Route::get('/orders/{order:uuid}/edit', ...): a custom key is still a key the caller chooses.
    // expect: laravel-idor-route-model-binding
    public function edit(Order $order)
    {
        return view('orders.edit', compact('order'));
    }

    // expect: laravel-idor-route-model-binding
    public function update(Request $request, Order $order)
    {
        $order->update($request->validated());
        return redirect()->route('orders.show', $order);
    }

    // expect: laravel-idor-route-model-binding
    public function destroy(Order $order)
    {
        $order->delete();
        return response()->noContent();
    }

    // A nullable type and an aliased import are still models.
    // expect: laravel-idor-route-model-binding
    public function bill(?Bill $bill)
    {
        return $bill;
    }

    // A model from a domain namespace with a Models segment.
    // expect: laravel-idor-route-model-binding
    public function cart(Cart $cart, PdfService $pdf)
    {
        return $pdf->render($cart);
    }

    // The guard checks the status, not the owner: still reported.
    // expect: laravel-idor-route-model-binding
    public function pay(Order $order)
    {
        abort_if($order->status !== 'open', 409);
        return $order;
    }

    // Logging the user is not a check.
    // expect: laravel-idor-route-model-binding
    public function audit(Order $order)
    {
        Log::info('order viewed', ['order' => $order->id, 'by' => auth()->id()]);
        return $order;
    }

    // A class-level ability does not check the bound row.
    // expect: laravel-idor-route-model-binding
    public function classOnly(Order $order)
    {
        $this->authorize('viewAny', Order::class);
        return $order;
    }

    // The policy result is stored and never used.
    // expect: laravel-idor-route-model-binding
    public function ignored(Order $order)
    {
        $allowed = Gate::allows('view', $order);
        return $order;
    }

    // The owner check is on another object.
    // expect: laravel-idor-route-model-binding
    public function wrongObject(Request $request, Order $order, Bill $bill)
    {
        abort_unless($bill->user_id === $request->user()->id, 403);
        return $order;
    }

    // Only the parent is checked; without scopeBindings() any project id works under that team.
    // expect: laravel-idor-route-model-binding
    public function project(Team $team, Project $project)
    {
        abort_unless($team->users()->whereKey(auth()->id())->exists(), 403);
        return $project;
    }
}
