<?php
// Realistic sample (false positive check): a FormRequest policy check and a ->can() route.

namespace App\Http\Controllers;

use App\Http\Requests\StoreCommentRequest;
use App\Models\Comment;
use App\Models\Post;
use Illuminate\Http\RedirectResponse;

class CommentController extends Controller
{
    // expect: laravel-idor-route-model-binding gate-drops
    public function store(StoreCommentRequest $request, Post $post): RedirectResponse
    {
        $post->comments()->create([
            'body' => $request->validated('body'),
            'user_id' => $request->user()->id,
        ]);

        return back();
    }

    // expect: laravel-idor-route-model-binding gate-drops
    public function destroy(Comment $comment): RedirectResponse
    {
        $comment->delete();

        return back();
    }
}
