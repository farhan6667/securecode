<?php
// Test fixture for semgrep/laravel-authz.yml: an empty $guarded list must be reported,
// an explicit $fillable list must not.

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Invoice extends Model
{
    // expect: laravel-mass-assignment
    protected $guarded = [];
}

class Profile extends Model
{
    protected $fillable = ['bio', 'avatar_path'];

    protected $guarded = ['id', 'user_id', 'is_admin'];
}
