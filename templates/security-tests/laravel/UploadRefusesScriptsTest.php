<?php
// File upload: a PHP file must be refused, also when it is renamed to look like an image, and
// nothing may be stored on any disk. Both the 'local' disk (where StoreAvatarRequest says to store
// uploads) and the 'public' disk are faked, so a controller that writes to either one is caught.
// Change the URL and the field name to your own upload route, and fake any other disk you use.

use App\Models\User;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Storage;

dataset('bad files', [
    'php file' => ['shell.php', "<?php echo 'x';"],
    'double extension' => ['shell.php.jpg', "<?php echo 'x';"],
    'php content as jpg' => ['avatar.jpg', "<?php echo 'x';"],
    'short echo tag as jpg' => ['avatar.jpg', "<?= 'x' ?>"],
    'phtml' => ['shell.phtml', "<?php echo 'x';"],
]);

it('refuses a script upload and stores nothing', function (string $name, string $content) {
    Storage::fake('local');
    Storage::fake('public');
    $user = User::factory()->create();

    $file = UploadedFile::fake()->createWithContent($name, $content);

    $this->actingAs($user)
        ->postJson('/api/profile/avatar', ['avatar' => $file])
        ->assertStatus(422);

    expect(Storage::disk('local')->allFiles())->toBeEmpty();
    expect(Storage::disk('public')->allFiles())->toBeEmpty();
})->with('bad files');

it('refuses a real image with PHP code after the first megabyte', function () {
    Storage::fake('local');
    Storage::fake('public');
    $user = User::factory()->create();

    // A valid PNG padded past 1 MB with an open tag at the end, still under the 2048 KB limit.
    $png = UploadedFile::fake()->image('big.png', 10, 10);
    $content = file_get_contents($png->getRealPath())
        .str_repeat("\0", 1024 * 1024 + 10)
        ."<?php echo 'x';";
    $file = UploadedFile::fake()->createWithContent('big.png', $content);

    $this->actingAs($user)
        ->postJson('/api/profile/avatar', ['avatar' => $file])
        ->assertStatus(422);

    expect(Storage::disk('local')->allFiles())->toBeEmpty();
    expect(Storage::disk('public')->allFiles())->toBeEmpty();
});

it('accepts a real image', function () {
    Storage::fake('local');
    Storage::fake('public');
    $user = User::factory()->create();

    $this->actingAs($user)
        ->postJson('/api/profile/avatar', ['avatar' => UploadedFile::fake()->image('me.png', 200, 200)])
        ->assertSuccessful();
});
