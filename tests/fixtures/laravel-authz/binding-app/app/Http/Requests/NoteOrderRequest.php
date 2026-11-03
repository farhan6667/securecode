<?php
// Test fixture: the generated FormRequest stub changed to "return true", which checks nothing. The
// commented-out line must not count either.

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class NoteOrderRequest extends FormRequest
{
    public function authorize(): bool
    {
        // return $this->user()->can('update', $this->route('order'));
        return true;
    }

    public function rules(): array
    {
        return ['note' => ['nullable', 'string', 'max:500']];
    }
}
