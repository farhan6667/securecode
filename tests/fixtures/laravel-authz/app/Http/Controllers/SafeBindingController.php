<?php
// Test fixture for semgrep/laravel-authz.yml: route model binding with a check. Nothing in this file
// may be reported.

namespace App\Http\Controllers;

use App\Models\Order;
use App\Models\Category;
use App\Models\Invoice;
use App\Models\Article;
use App\Models\Document;
use App\Services\PdfService;
use Illuminate\Http\Request;
use Illuminate\Routing\Controllers\HasMiddleware;
use Illuminate\Routing\Controllers\Middleware;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;

class SafeBindingController extends Controller
{
    public function show(Order $order)
    {
        $this->authorize('view', $order);
        return $order;
    }

    public function edit(Order $order)
    {
        Gate::authorize('update', $order);
        return view('orders.edit', compact('order'));
    }

    public function update(Request $request, Order $order)
    {
        if (! Gate::allows('update', $order)) {
            abort(403);
        }
        $order->update($request->validated());
        return $order;
    }

    public function destroy(Request $request, Order $order)
    {
        abort_unless($request->user()->can('delete', $order), 403);
        $order->delete();
        return back();
    }

    public function cancel(Request $request, Order $order)
    {
        if ($request->user()->cannot('cancel', $order)) {
            abort(403);
        }
        $order->cancel();
        return $order;
    }

    public function owner(Order $order)
    {
        abort_if($order->user_id !== auth()->id(), 403);
        return $order;
    }

    public function ownerUnless(Request $request, Order $order)
    {
        abort_unless($order->user_id === $request->user()->id, 404);
        return $order;
    }

    public function ownerIf(Order $order)
    {
        if ($order->user_id != Auth::id()) {
            abort(403);
        }
        return $order;
    }

    public function ownerIs(Order $order)
    {
        abort_unless($order->user->is(auth()->user()), 403);
        return $order;
    }

    public function ownerThrow(Request $request, Order $order)
    {
        $user = $request->user();
        throw_unless($order->user()->is($user), new \RuntimeException('forbidden'));
        return $order;
    }

    public function forUser(Order $order)
    {
        Gate::forUser(auth()->user())->authorize('view', $order);
        return $order;
    }

    public function asUser(Request $request, Document $document)
    {
        $this->authorizeForUser($request->user(), 'view', $document);
        return $document;
    }

    public function shortCircuit(Document $document)
    {
        Gate::denies('view', $document) && abort(403);
        return $document;
    }

    public function earlyReturn(Request $request, Document $document)
    {
        if ($request->user()->id !== $document->user_id) {
            return response()->json(['message' => 'Forbidden'], 403);
        }
        return $document;
    }

    public function isNot(Request $request, Document $document)
    {
        abort_if($request->user()->isNot($document->owner), 403);
        return $document;
    }

    public function reload(Request $request, Document $document)
    {
        // Loading it again through the caller's relation 404s for anyone else's id.
        $document = $request->user()->documents()->findOrFail($document->getKey());
        return $document;
    }

    public function inspect(Document $document)
    {
        return Gate::inspect('view', $document)->allowed() ? $document : abort(403);
    }

    public function adminOnly(Document $document)
    {
        // A gate with only an ability name is a role check.
        Gate::authorize('admin');
        return $document;
    }

    // Shown only when published: public content, ownership does not apply.
    public function article(Article $article)
    {
        abort_unless($article->isPublished(), 404);
        return $article;
    }

    // Categories are public reference data on purpose.
    // securecode: public-object
    public function category(Category $category)
    {
        return $category;
    }

    public function receipt(Order $order) // securecode: public-object
    {
        return $order->receipt;
    }

    // Not a model: a request, a service and a scalar.
    public function render(Request $request, PdfService $pdf, int $page)
    {
        return $pdf->page($page);
    }

    // Not a public action.
    protected function present(Order $order)
    {
        return $order->only('id', 'total');
    }
}

class OrderPolicyController extends Controller
{
    public function __construct()
    {
        $this->authorizeResource(Order::class, 'order');
    }

    public function show(Order $order)
    {
        return $order;
    }

    public function update(Request $request, Order $order)
    {
        $order->update($request->validated());
        return $order;
    }
}

// Admin area: every method sits behind an admin-only can: middleware set in the controller.
class AdminOrderController extends Controller
{
    public function __construct()
    {
        $this->middleware('can:manage-orders');
    }

    public function show(Order $order)
    {
        return $order;
    }
}

class AdminInvoiceController extends Controller
{
    public function __construct()
    {
        $this->middleware(['auth', 'role:admin']);
    }

    public function show(Invoice $invoice)
    {
        return $invoice;
    }
}

class InvoiceEditController extends Controller
{
    public function __construct()
    {
        $this->middleware('can:update,invoice')->only(['edit', 'update']);
    }

    public function edit(Invoice $invoice)
    {
        return $invoice;
    }
}

// Laravel 11 style controller middleware.
class StaffInvoiceController extends Controller implements HasMiddleware
{
    public static function middleware(): array
    {
        return [
            'auth',
            new Middleware('can:view,invoice', only: ['show']),
        ];
    }

    public function show(Invoice $invoice)
    {
        return $invoice;
    }
}
