<?php

declare(strict_types=1);

namespace WordPress\OpenAiAiProvider\Authentication;

use Throwable;

/**
 * Stores one short-lived device authorization session per WordPress user.
 *
 * @since 1.1.0
 */
final class OAuthSessionStore
{
    public const SESSION_TTL = 900;

    private const TRANSIENT_PREFIX = '_ai_openai_oauth_session_';
    private const POLL_LOCK_PREFIX = '_ai_openai_oauth_poll_lock_';

    /**
     * Creates or replaces a user's device authorization session.
     *
     * @since 1.1.0
     *
     * @param int                  $userId     WordPress user ID.
     * @param array<string, mixed> $deviceData Device endpoint data.
     * @return array<string, mixed>|object Safe session response or WP_Error.
     */
    public function create(int $userId, array $deviceData)
    {
        if ($userId < 1) {
            return OAuthError::create(
                'oauth_user_invalid',
                'A valid WordPress user is required for OAuth.',
                401
            );
        }

        $deviceAuthId = $this->boundedString($deviceData['device_auth_id'] ?? null, 1024);
        $userCode = $this->boundedString($deviceData['user_code'] ?? null, 128);
        $verificationUrl = $this->boundedString($deviceData['verification_url'] ?? null, 2048);
        if (
            $deviceAuthId === ''
            || $userCode === ''
            || !OAuthConfig::isAllowedVerificationUrl($verificationUrl)
        ) {
            return OAuthError::create(
                'oauth_device_session_invalid',
                'The device authorization response cannot be stored safely.',
                502
            );
        }

        $interval = $this->integerValue($deviceData['interval'] ?? null, 5);
        $interval = max(3, min(30, $interval));
        $now = time();
        $session = [
            'session_id' => $this->createSessionId(),
            'user_id' => $userId,
            'status' => 'pending',
            'device_auth_id' => $deviceAuthId,
            'user_code' => $userCode,
            'verification_url' => $verificationUrl,
            'interval' => $interval,
            'created_at' => $now,
            'expires_at' => $now + self::SESSION_TTL,
            'next_poll_at' => $now + $interval,
            'cancelled' => false,
            'error_code' => '',
        ];

        $saved = $this->save($userId, $session);
        if ($saved !== true) {
            return $saved;
        }

        return $this->toSafeResponse($session);
    }

    /**
     * Begins one poll after validating ownership, expiry, cancellation, and cadence.
     *
     * The next permitted poll is persisted before the HTTP call so rapid or
     * concurrent requests cannot intentionally bypass the upstream interval.
     *
     * @since 1.1.0
     *
     * @return array<string, mixed>|object Internal session or WP_Error.
     */
    public function beginPoll(int $userId, string $sessionId)
    {
        $session = $this->get($userId, $sessionId);
        if (!is_array($session)) {
            return $session;
        }

        if ($this->booleanValue($session['cancelled'] ?? null) || $session['status'] === 'cancelled') {
            return OAuthError::create(
                'oauth_session_cancelled',
                'The OAuth session was cancelled.',
                409
            );
        }
        if ($session['status'] !== 'pending') {
            return OAuthError::create(
                'oauth_session_not_pending',
                'The OAuth session is not waiting for approval.',
                409
            );
        }

        $now = time();
        $nextPollAt = $this->integerValue($session['next_poll_at'] ?? null);
        if ($nextPollAt > $now) {
            return OAuthError::create(
                'oauth_poll_too_soon',
                'Wait before checking the OAuth approval again.',
                429,
                ['retry_after' => max(1, $nextPollAt - $now)]
            );
        }

        $session['next_poll_at'] = $now + $this->integerValue($session['interval'] ?? null, 5);
        $saved = $this->save($userId, $session);
        if ($saved !== true) {
            return $saved;
        }

        return $session;
    }

    /**
     * Confirms that a session still belongs to the user and has not been cancelled.
     *
     * @since 1.1.0
     *
     * @param list<string> $allowedStatuses Allowed active statuses.
     * @return array<string, mixed>|object Internal session or WP_Error.
     */
    public function assertActive(int $userId, string $sessionId, array $allowedStatuses = ['pending'])
    {
        $session = $this->get($userId, $sessionId);
        if (!is_array($session)) {
            return $session;
        }

        if ($this->booleanValue($session['cancelled'] ?? null) || $session['status'] === 'cancelled') {
            return OAuthError::create(
                'oauth_session_cancelled',
                'The OAuth session was cancelled.',
                409
            );
        }
        if (!in_array($session['status'], $allowedStatuses, true)) {
            return OAuthError::create(
                'oauth_session_state_changed',
                'The OAuth session state changed before it could complete.',
                409
            );
        }

        return $session;
    }

    /**
     * Marks a pending session as exchanging its approved code.
     *
     * @since 1.1.0
     *
     * @return true|object True or WP_Error.
     */
    public function markExchanging(int $userId, string $sessionId)
    {
        $session = $this->assertActive($userId, $sessionId, ['pending']);
        if (!is_array($session)) {
            return $session;
        }

        $session['status'] = 'exchanging';

        return $this->save($userId, $session);
    }

    /**
     * Restores an exchanging session to pending after a retryable upstream error.
     *
     * @since 1.1.0
     *
     * @return true|object True or WP_Error.
     */
    public function markPending(int $userId, string $sessionId)
    {
        $session = $this->assertActive($userId, $sessionId, ['exchanging']);
        if (!is_array($session)) {
            return $session;
        }

        $session['status'] = 'pending';

        return $this->save($userId, $session);
    }

    /**
     * Marks a session as successfully approved and removes device secrets.
     *
     * @since 1.1.0
     *
     * @return true|object True or WP_Error.
     */
    public function markApproved(int $userId, string $sessionId)
    {
        $session = $this->get($userId, $sessionId);
        if (!is_array($session)) {
            return $session;
        }

        if ($this->booleanValue($session['cancelled'] ?? null) || $session['status'] === 'cancelled') {
            return OAuthError::create(
                'oauth_session_cancelled',
                'The OAuth session was cancelled.',
                409
            );
        }

        $session['status'] = 'approved';
        $session['device_auth_id'] = '';
        $session['user_code'] = '';
        $session['cancelled'] = false;

        return $this->save($userId, $session);
    }

    /**
     * Records a safe failure code and removes device secrets.
     *
     * @since 1.1.0
     *
     * @return true|object True or WP_Error.
     */
    public function markError(int $userId, string $sessionId, string $errorCode)
    {
        $session = $this->get($userId, $sessionId);
        if (!is_array($session)) {
            return $session;
        }

        if ($this->booleanValue($session['cancelled'] ?? null) || $session['status'] === 'cancelled') {
            return true;
        }

        $session['status'] = 'error';
        $session['device_auth_id'] = '';
        $session['user_code'] = '';
        $session['error_code'] = (string) preg_replace('/[^a-z0-9_-]/', '', strtolower($errorCode));

        return $this->save($userId, $session);
    }

    /**
     * Cancels a session owned by the current WordPress user.
     *
     * Keeping a short cancelled marker prevents an already-running poll from
     * exchanging or storing credentials after cancellation.
     *
     * @since 1.1.0
     *
     * @return true|object True or WP_Error.
     */
    public function cancel(int $userId, string $sessionId)
    {
        $session = $this->get($userId, $sessionId);
        if (!is_array($session)) {
            return $session;
        }

        $session['status'] = 'cancelled';
        $session['cancelled'] = true;
        $session['device_auth_id'] = '';
        $session['user_code'] = '';

        return $this->save($userId, $session);
    }

    /**
     * Cancels any current session for a user, if present.
     *
     * @since 1.1.0
     */
    public function cancelCurrent(int $userId): void
    {
        $session = $this->getRaw($userId);
        if (!is_array($session) || !isset($session['session_id']) || !is_string($session['session_id'])) {
            return;
        }

        $this->cancel($userId, $session['session_id']);
    }

    /**
     * Gets the safe, current-user session summary used by REST status.
     *
     * @since 1.1.0
     *
     * @return array<string, mixed>|null
     */
    public function getSafeStatus(int $userId): ?array
    {
        $rawSession = $this->getRaw($userId);
        if (!is_array($rawSession)) {
            return null;
        }

        /** @var array<string, mixed> $session */
        $session = $rawSession;
        if (!$this->isInternallyValid($session, $userId)) {
            return null;
        }

        if ($this->integerValue($session['expires_at'] ?? null) <= time()) {
            $this->delete($userId);

            return null;
        }

        return $this->toSafeResponse($session);
    }

    /**
     * Creates the per-user lock used to serialize device polls.
     *
     * @since 1.1.0
     */
    public function pollLock(int $userId): OptionLock
    {
        return new OptionLock(self::POLL_LOCK_PREFIX . $userId, 20);
    }

    /**
     * Gets an owned, unexpired session.
     *
     * @return array<string, mixed>|object Internal session or WP_Error.
     */
    private function get(int $userId, string $sessionId)
    {
        $rawSession = $this->getRaw($userId);
        if (!is_array($rawSession)) {
            return OAuthError::create(
                'oauth_session_missing',
                'No OAuth session was found for this user.',
                404
            );
        }

        /** @var array<string, mixed> $session */
        $session = $rawSession;
        if (!$this->isInternallyValid($session, $userId)) {
            return OAuthError::create(
                'oauth_session_invalid',
                'The OAuth session is invalid.',
                409
            );
        }
        $storedSessionId = $this->stringValue($session['session_id'] ?? null);
        if (!hash_equals($storedSessionId, $sessionId)) {
            return OAuthError::create(
                'oauth_session_not_owned',
                'The OAuth session does not belong to this request.',
                403
            );
        }
        if ($this->integerValue($session['expires_at'] ?? null) <= time()) {
            $this->delete($userId);

            return OAuthError::create(
                'oauth_session_expired',
                'The OAuth session expired. Start a new login.',
                410
            );
        }

        return $session;
    }

    /**
     * Reads the current per-user transient.
     *
     * @return mixed
     */
    private function getRaw(int $userId)
    {
        if (!function_exists('get_transient')) {
            return null;
        }

        $value = get_transient($this->transientName($userId));

        return $value === false ? null : $value;
    }

    /**
     * Saves a transient for no longer than the original 15-minute deadline.
     *
     * @param array<string, mixed> $session Internal session.
     * @return true|object True or WP_Error.
     */
    private function save(int $userId, array $session)
    {
        if (!function_exists('set_transient')) {
            return OAuthError::create(
                'oauth_session_storage_unavailable',
                'WordPress transient storage is unavailable.',
                500
            );
        }

        $remaining = max(
            1,
            min(self::SESSION_TTL, $this->integerValue($session['expires_at'] ?? null) - time())
        );
        if (!set_transient($this->transientName($userId), $session, $remaining)) {
            return OAuthError::create(
                'oauth_session_storage_failed',
                'The OAuth session could not be saved.',
                500
            );
        }

        return true;
    }

    /**
     * Deletes a per-user transient.
     */
    private function delete(int $userId): void
    {
        if (function_exists('delete_transient')) {
            delete_transient($this->transientName($userId));
        }
    }

    /**
     * Converts an internal session to a token-free response.
     *
     * @param array<string, mixed> $session Internal session.
     * @return array<string, mixed>
     */
    private function toSafeResponse(array $session): array
    {
        $retryAfter = max(0, $this->integerValue($session['next_poll_at'] ?? null) - time());

        return [
            'session_id' => $this->stringValue($session['session_id'] ?? null),
            'status' => $this->stringValue($session['status'] ?? null),
            'user_code' => $this->stringValue($session['user_code'] ?? null),
            'verification_url' => $this->stringValue($session['verification_url'] ?? null),
            'interval' => $this->integerValue($session['interval'] ?? null),
            'expires_at' => $this->integerValue($session['expires_at'] ?? null),
            'retry_after' => $retryAfter,
            'error_code' => $this->stringValue($session['error_code'] ?? null),
        ];
    }

    /**
     * Validates the internal session shape and ownership.
     *
     * @param array<string, mixed> $session Internal session.
     */
    private function isInternallyValid(array $session, int $userId): bool
    {
        return isset(
            $session['session_id'],
            $session['user_id'],
            $session['status'],
            $session['device_auth_id'],
            $session['user_code'],
            $session['verification_url'],
            $session['interval'],
            $session['expires_at'],
            $session['next_poll_at'],
            $session['cancelled'],
            $session['error_code']
        )
            && is_string($session['session_id'])
            && preg_match('/\A[a-f0-9]{48}\z/', $session['session_id']) === 1
            && is_numeric($session['user_id'])
            && $this->integerValue($session['user_id']) === $userId
            && is_string($session['status'])
            && is_string($session['device_auth_id'])
            && is_string($session['user_code'])
            && is_string($session['verification_url'])
            && is_numeric($session['interval'])
            && is_numeric($session['expires_at'])
            && is_numeric($session['next_poll_at']);
    }

    /**
     * Returns a deterministic, bounded transient name.
     */
    private function transientName(int $userId): string
    {
        return self::TRANSIENT_PREFIX . $userId;
    }

    /**
     * Creates a random public session identifier.
     */
    private function createSessionId(): string
    {
        try {
            return bin2hex(random_bytes(24));
        } catch (Throwable $throwable) {
            return substr(hash('sha256', uniqid(self::TRANSIENT_PREFIX, true)), 0, 48);
        }
    }

    /**
     * Returns a trimmed, bounded string or an empty string.
     *
     * @param mixed $value  Possible string.
     * @param int   $length Maximum byte length.
     */
    private function boundedString($value, int $length): string
    {
        if (!is_string($value)) {
            return '';
        }

        $value = trim($value);
        if ($value === '' || strlen($value) > $length) {
            return '';
        }

        return $value;
    }

    /**
     * Converts a numeric value to an integer without casting arbitrary mixed data.
     *
     * @param mixed $value   Possible numeric value.
     * @param int   $default Default value.
     */
    private function integerValue($value, int $default = 0): int
    {
        return is_numeric($value) ? (int) $value : $default;
    }

    /**
     * Returns a string value without casting arbitrary mixed data.
     *
     * @param mixed $value Possible string.
     */
    private function stringValue($value): string
    {
        return is_string($value) ? $value : '';
    }

    /**
     * Returns a strict boolean value.
     *
     * @param mixed $value Possible boolean.
     */
    private function booleanValue($value): bool
    {
        return $value === true;
    }
}
