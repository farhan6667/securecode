<?php
// Test fixture for semgrep/laravel-authz.yml. Nothing in this file may be reported.

namespace App\Http\Controllers;

use App\Models\Order;
use App\Http\Requests\UpdateOrderRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

class SafeOrderController extends Controller
{
    public function show(Request $request)
    {
        $order = Order::findOrFail($request->id);
        $this->authorize('view', $order);
        return $order;
    }

    public function edit(Request $request)
    {
        $order = Order::findOrFail($request->input('id'));
        if (! Gate::allows('update', $order)) {
            abort(403);
        }
        return $order;
    }

    public function export(Request $request)
    {
        $order = Order::find($request->id);
        abort_unless($request->user()->can('export', $order), 403);
        return $order;
    }

    public function mine(Request $request)
    {
        return auth()->user()->orders()->findOrFail($request->id);
    }

    public function mineWhere(Request $request)
    {
        return $request->user()->orders()->where('id', $request->id)->firstOrFail();
    }

    public function belongs(Request $request)
    {
        return Order::whereBelongsTo($request->user())->where('id', $request->id)->firstOrFail();
    }

    public function update(UpdateOrderRequest $request, $id)
    {
        $order = auth()->user()->orders()->findOrFail($id);
        $order->update($request->validated());
        return $order;
    }

    public function store(UpdateOrderRequest $request)
    {
        return $request->user()->orders()->create($request->validated());
    }

    public function catalogue(Request $request)
    {
        return Order::find($request->id); // securecode: public-object
    }

    // securecode: public-object
    public function publicReceipt($id)
    {
        $order = Order::findOrFail($id);
        return view('receipt', ['order' => $order]);
    }

    public function membership(Request $request)
    {
        // The key is the caller's own id.
        return Order::query()->whereKey($request->user()->id)->exists();
    }

    public function byName(Request $request)
    {
        // Lookups by something other than the id are out of scope for this rule.
        return Order::where('name', $request->name)->first();
    }
}
