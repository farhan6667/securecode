<?php

namespace App\Http\Controllers;

use App\Models\Post;
use Illuminate\View\View;

class BlogController extends Controller
{
    public function show(Post $post): View
    {
        abort_unless($post->isPublished(), 404);

        return view('blog.show', [
            'post' => $post->load('author'),
        ]);
    }
}
