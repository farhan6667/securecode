<?php
// Test fixture: a FormRequest whose authorize() checks the signed-in user against the bound order.

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class UpdateOrderRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('update', $this->route('order'));
    }

    public function rules(): array
    {
        return ['note' => ['nullable', 'string', 'max:500']];
    }
}
