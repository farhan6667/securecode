<?php
// Cross-user access (IDOR / BOLA). User B must not read, change, delete or export user A's order.
// One dataset row per row of .security/authz-matrix.md. Change Order, the factory relation and the
// URLs to your own routes. 403 and 404 both count as refused.

use App\Models\Order;
use App\Models\User;

beforeEach(function () {
    $this->owner = User::factory()->create();
    $this->other = User::factory()->create();
    $this->order = Order::factory()->for($this->owner)->create();
});

dataset('order routes', [
    'show' => ['getJson', '/api/orders/%d'],
    'update' => ['putJson', '/api/orders/%d'],
    'patch' => ['patchJson', '/api/orders/%d'],
    'delete' => ['deleteJson', '/api/orders/%d'],
    'export' => ['getJson', '/api/orders/%d/export'],
]);

it('refuses another signed-in user', function (string $method, string $url) {
    $response = $this->actingAs($this->other)->{$method}(sprintf($url, $this->order->id), ['status' => 'cancelled']);

    expect($response->status())->toBeIn([403, 404]);
    $this->assertModelExists($this->order);
    expect($this->order->fresh()->status)->toBe($this->order->status);
})->with('order routes');

it('refuses a guest', function (string $method, string $url) {
    $this->{$method}(sprintf($url, $this->order->id))->assertUnauthorized();
})->with('order routes');

it('still lets the owner in', function () {
    $this->actingAs($this->owner)->getJson("/api/orders/{$this->order->id}")->assertOk();
});
