<?php
// Test fixture for semgrep/laravel-authz.yml: resource controllers with route model binding.
// A line marked "expect: <rule id>" means the next line must produce that finding.

namespace App\Http\Controllers;

use App\Models\Invoice;
use App\Models\Ticket;
use Illuminate\Http\Request;

// Route::resource('tickets', TicketController::class) with no policy anywhere.
class TicketController extends Controller
{
    public function index(Request $request)
    {
        return $request->user()->tickets;
    }

    // expect: laravel-idor-route-model-binding
    public function show(Ticket $ticket)
    {
        return $ticket;
    }

    // expect: laravel-idor-route-model-binding
    public function update(Request $request, Ticket $ticket)
    {
        $ticket->fill($request->only('title'))->save();
        return $ticket;
    }

    // expect: laravel-idor-route-model-binding
    public function destroy(Ticket $ticket)
    {
        $ticket->delete();
        return back();
    }
}

// authorizeResource() maps the resource methods to the policy, but not a custom download().
class InvoiceResourceController extends Controller
{
    public function __construct()
    {
        $this->authorizeResource(Invoice::class, 'invoice');
    }

    public function show(Invoice $invoice)
    {
        return $invoice;
    }

    public function destroy(Invoice $invoice)
    {
        $invoice->delete();
        return back();
    }

    // expect: laravel-idor-route-model-binding
    public function download(Invoice $invoice)
    {
        return response()->download($invoice->path);
    }
}

// The can: middleware only covers edit(); show() is open.
class InvoicePartialMiddlewareController extends Controller
{
    public function __construct()
    {
        $this->middleware('can:update,invoice')->only(['edit']);
    }

    public function edit(Invoice $invoice)
    {
        return $invoice;
    }

    // expect: laravel-idor-route-model-binding
    public function show(Invoice $invoice)
    {
        return $invoice;
    }
}

// ->except() leaves the listed method open.
class InvoiceExceptOpenController extends Controller
{
    public function __construct()
    {
        $this->middleware('can:view,invoice')->except(['show']);
    }

    // expect: laravel-idor-route-model-binding
    public function show(Invoice $invoice)
    {
        return $invoice;
    }
}

// A role middleware that is not an admin or staff role does not prove ownership.
class InvoiceCustomerController extends Controller
{
    public function __construct()
    {
        $this->middleware('role:customer');
    }

    // expect: laravel-idor-route-model-binding
    public function show(Invoice $invoice)
    {
        return $invoice;
    }
}

// The marker on a different method does not cover this one.
class InvoiceMarkerController extends Controller
{
    // securecode: public-object
    public function preview(Invoice $invoice)
    {
        return $invoice->summary;
    }

    // expect: laravel-idor-route-model-binding
    public function full(Invoice $invoice)
    {
        return $invoice;
    }
}
