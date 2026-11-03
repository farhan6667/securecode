<?php
// Test fixture for semgrep/laravel-authz.yml: mass assignment that must be reported.

namespace App\Http\Controllers;

use App\Models\Profile;
use Illuminate\Http\Request;

class ProfileMassAssignController extends Controller
{
    public function store(Request $request)
    {
        // expect: laravel-mass-assignment
        return Profile::create($request->all());
    }

    public function update(Request $request)
    {
        $profile = $request->user()->profile;
        // expect: laravel-mass-assignment
        $profile->update($request->all());
        return $profile;
    }

    public function fill(Request $request)
    {
        $profile = $request->user()->profile;
        // expect: laravel-mass-assignment
        $profile->fill(request()->all())->save();
        return $profile;
    }

    public function storeViaVariable(Request $request)
    {
        $data = $request->all();
        $data['source'] = 'web';
        // expect: laravel-mass-assignment
        return Profile::create($data);
    }

    public function updateFromPost(Request $request)
    {
        $profile = $request->user()->profile;
        // expect: laravel-mass-assignment
        $profile->update($request->post());
        return $profile;
    }

    public function updateFromInput(Request $request)
    {
        $profile = $request->user()->profile;
        // expect: laravel-mass-assignment
        $profile->update($request->input());
        return $profile;
    }

    public function storeFromJson(Request $request)
    {
        // expect: laravel-mass-assignment
        return Profile::create($request->json()->all());
    }

    public function safeViaVariable(Request $request)
    {
        $data = $request->all();
        $data = array_intersect_key($data, array_flip(['bio']));
        $request->user()->profile->update($data);
        $bio = $request->input('bio');
        $request->user()->profile->update(['bio' => $bio]);
        return $request->user()->profile;
    }

    public function safe(Request $request)
    {
        $data = $request->validate(['bio' => 'string|max:500']);
        $request->user()->profile->update($data);
        $request->user()->profile->update($request->only(['bio']));
        return $request->user()->profile;
    }
}
