<?php
// Realistic sample (false positive check): an admin resource behind can:access-admin in routes/web.php.
// Semgrep alone reports the bound users; secgate's route context must drop every one ("gate-drops").

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Http\Requests\Admin\UpdateUserRequest;
use App\Models\User;
use Illuminate\Http\Request;

class UserController extends Controller
{
    public function index(Request $request)
    {
        return view('admin.users.index', ['users' => User::query()->paginate(50)]);
    }

    // expect: laravel-idor-route-model-binding gate-drops
    public function show(User $user)
    {
        return view('admin.users.show', compact('user'));
    }

    // expect: laravel-idor-route-model-binding gate-drops
    public function edit(User $user)
    {
        return view('admin.users.edit', compact('user'));
    }

    // expect: laravel-idor-route-model-binding gate-drops
    public function update(UpdateUserRequest $request, User $user)
    {
        $user->update($request->validated());
        return redirect()->route('admin.users.show', $user);
    }

    // expect: laravel-idor-route-model-binding gate-drops
    public function destroy(User $user)
    {
        $user->delete();
        return redirect()->route('admin.users.index');
    }

    // expect: laravel-idor-route-model-binding gate-drops
    public function impersonate(Request $request, User $user)
    {
        $request->session()->put('impersonate', $user->id);
        return redirect('/');
    }
}
