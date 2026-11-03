<?php
// VerifyWebhookSignature: accepts a webhook only when its HMAC-SHA256 signature matches and its
// timestamp is recent. It fails closed: no secret configured, a missing header or a bad value all
// return 401. The signature covers "timestamp.body", so an old body cannot be replayed with a new
// timestamp. Within the tolerance window a replay is still possible: store each event id and
// refuse duplicates in the controller.
// Most providers (Stripe, GitHub, Paddle) have their own header names and format. Use their SDK's
// verifier when it exists, and keep the same rules: hash_equals, a timestamp window, fail closed.
// Secret: WEBHOOK_SECRET in .env, read through config('services.webhooks.secret').

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class VerifyWebhookSignature
{
    // Seconds a signed request stays valid. Keep it short; allow for clock drift.
    private const TOLERANCE = 300;

    public function handle(Request $request, Closure $next): Response
    {
        $secret = (string) config('services.webhooks.secret');
        $timestamp = (string) $request->header('X-Webhook-Timestamp', '');
        $signature = strtolower((string) $request->header('X-Webhook-Signature', ''));

        if (str_starts_with($signature, 'sha256=')) {
            $signature = substr($signature, 7);
        }

        if ($secret === '' || $signature === '' || ! ctype_digit($timestamp) || strlen($timestamp) > 12) {
            abort(401);
        }

        if (abs(time() - (int) $timestamp) > self::TOLERANCE) {
            abort(401);
        }

        $expected = hash_hmac('sha256', $timestamp.'.'.$request->getContent(), $secret);

        if (! hash_equals($expected, $signature)) {
            abort(401);
        }

        return $next($request);
    }
}
