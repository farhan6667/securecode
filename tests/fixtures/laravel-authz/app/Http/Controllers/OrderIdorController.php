<?php
// Test fixture for semgrep/laravel-authz.yml. Every lookup below must be reported.
// A line marked "expect: <rule id>" means the next line must produce that finding.

namespace App\Http\Controllers;

use App\Models\Order;
use Illuminate\Http\Request;

class OrderIdorController extends Controller
{
    public function show(Request $request)
    {
        // expect: laravel-idor-unscoped-lookup
        $order = Order::find($request->id);
        return response()->json($order);
    }

    public function edit(Request $request)
    {
        // expect: laravel-idor-unscoped-lookup
        return Order::findOrFail($request->input('order_id'));
    }

    public function export(Request $request)
    {
        // expect: laravel-idor-unscoped-lookup
        $rows = Order::where('id', $request->query('id'))->get();
        return $rows;
    }

    public function destroy($id)
    {
        // expect: laravel-idor-unscoped-lookup
        $order = Order::findOrFail($id);
        $order->delete();
        return response()->noContent();
    }

    public function download(int $orderId)
    {
        // expect: laravel-idor-unscoped-lookup
        $order = Order::query()->where('id', $orderId)->firstOrFail();
        return response()->download($order->path);
    }

    // securecode: public-object
    public function publicStatus($id)
    {
        return Order::findOrFail($id)->status;
    }

    public function update()
    {
        // The marker on publicStatus() above must not cover this method.
        // expect: laravel-idor-unscoped-lookup
        $order = Order::findOrFail(request('id'));
        $order->save();
        return $order;
    }

    // securecode: public-object
    public function publicSummary($id)
    {
        return Order::findOrFail($id)->total;
    }
    #[Get('/orders/{orderId}/secret')] public function secret($orderId)
    {
        // The marker on publicSummary() above must not cover a method that opens with an attribute.
        // expect: laravel-idor-unscoped-lookup
        return Order::findOrFail($orderId);
    }
}
