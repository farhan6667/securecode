<?php
// Upload validation: type checked from the file content, not the name; a size limit; and a second
// content check that refuses anything with PHP code in it (polyglot images).
// Store the file with $request->file('avatar')->store('avatars', 'local'): a random name on the
// stock Laravel 11 'local' disk, which is rooted at storage/app/private and is not web served (on
// Laravel 10 and older 'local' is storage/app, also outside public/). Do not put these uploads on the
// 'public' disk. Never use getClientOriginalName() for the stored path, and serve the files through
// a controller that checks the owner.
// Strongest fix for hidden code: re-encode the image (decode it and save a fresh PNG or WebP) and
// store only the re-encoded file. The content check below is a cheap first gate, not a replacement.
// SVG is left out on purpose: it can carry script. Allow it only after sanitizing it.

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Validator;

class StoreAvatarRequest extends FormRequest
{
    // Kilobytes. Set your own limit, and keep upload_max_filesize, post_max_size and the web
    // server's body limit in line with it.
    private const MAX_KB = 2048;

    public function authorize(): bool
    {
        return $this->user() !== null;
    }

    public function rules(): array
    {
        return [
            'avatar' => [
                'required',
                'file',
                'max:'.self::MAX_KB,
                // mimes and mimetypes both use the detected content type, not the extension.
                'mimes:jpg,jpeg,png,webp',
                'mimetypes:image/jpeg,image/png,image/webp',
                'dimensions:max_width=4000,max_height=4000',
            ],
        ];
    }

    public function after(): array
    {
        return [
            function (Validator $validator) {
                $file = $this->file('avatar');
                if (! $file || ! $file->isValid()) {
                    return;
                }

                $path = $file->getRealPath();
                if (@getimagesize($path) === false) {
                    $validator->errors()->add('avatar', 'The file is not a readable image.');

                    return;
                }

                // Read the whole file, up to the size limit, so code placed after the first
                // megabyte is still found.
                $content = file_get_contents($path, false, null, 0, self::MAX_KB * 1024);
                if ($content === false) {
                    $validator->errors()->add('avatar', 'The file could not be read.');

                    return;
                }

                // PHP open tags: <?php and <?=. The bare short tag "<?" is left out on purpose:
                // it appears by chance in compressed image data and would refuse real photos, and
                // short_open_tag is off in PHP's recommended php.ini. The real protection is
                // storing on the private 'local' disk and re-encoding the image (see the top).
                if (preg_match('/<\?(?:php|=)/i', $content) === 1) {
                    $validator->errors()->add('avatar', 'The file contains code.');
                }
            },
        ];
    }
}
