<?php
// Stored XSS round trip. Save a payload through a normal form, load the page that shows it, and
// check that it comes back escaped. Change the URLs and the field to a field your users can edit.
// Repeat for admin-managed fields (titles, banners, notices): pentests often find XSS there.

use App\Models\User;

dataset('payloads', [
    'script tag' => ['<script>alert(1)</script>'],
    'attribute break' => ['"><img src=x onerror=alert(1)>'],
    'svg' => ['<svg onload=alert(1)>'],
]);

it('shows user input escaped', function (string $payload) {
    $user = User::factory()->create();

    $this->actingAs($user)->patch('/profile', ['name' => $payload])->assertSessionHasNoErrors();

    $this->actingAs($user)->get('/profile')
        ->assertOk()
        ->assertDontSee($payload, false)
        ->assertSee(e($payload), false);
})->with('payloads');
