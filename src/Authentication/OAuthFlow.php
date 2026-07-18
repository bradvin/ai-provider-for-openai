<?php

declare(strict_types=1);

namespace WordPress\OpenAiAiProvider\Authentication;

/**
 * Coordinates device sessions, token exchange, mode selection, and disconnect.
 *
 * @since 1.1.0
 */
final class OAuthFlow
{
    /** @var OAuthClient */
    private $client;

    /** @var OAuthSessionStore */
    private $sessions;

    /** @var EncryptedTokenStore */
    private $tokenStore;

    /** @var OAuthTokenManager */
    private $tokenManager;

    /** @var AuthenticationMode */
    private $mode;

    /**
     * @since 1.1.0
     */
    public function __construct(
        ?OAuthClient $client = null,
        ?OAuthSessionStore $sessions = null,
        ?EncryptedTokenStore $tokenStore = null,
        ?OAuthTokenManager $tokenManager = null,
        ?AuthenticationMode $mode = null
    ) {
        $this->client = $client ?? new OAuthClient();
        $this->sessions = $sessions ?? new OAuthSessionStore();
        $this->tokenStore = $tokenStore ?? new EncryptedTokenStore();
        $this->tokenManager = $tokenManager ?? new OAuthTokenManager($this->tokenStore, $this->client);
        $this->mode = $mode ?? new AuthenticationMode($this->tokenStore);
    }

    /**
     * Starts a new per-user device authorization session.
     *
     * @since 1.1.0
     *
     * @return array<string, mixed>|object Safe device data or WP_Error.
     */
    public function start(int $userId)
    {
        if (!$this->tokenStore->isEncryptionAvailable()) {
            return OAuthError::create(
                'oauth_encryption_unavailable',
                'OpenSSL AES-256-GCM support and WordPress salts are required for OAuth.',
                500
            );
        }

        // Mark the old session cancelled before starting a replacement.
        $this->sessions->cancelCurrent($userId);

        $deviceData = $this->client->startDeviceAuthorization();
        if (!is_array($deviceData)) {
            return $deviceData;
        }

        return $this->sessions->create($userId, $deviceData);
    }

    /**
     * Polls once and completes an approved device authorization.
     *
     * The session is re-read before exchange and immediately before token
     * storage. This prevents a cancelled or foreign session from completing.
     * No OAuth token is included in the returned data.
     *
     * @since 1.1.0
     *
     * @return array<string, mixed>|object Safe poll status or WP_Error.
     */
    public function poll(int $userId, string $sessionId)
    {
        $lock = $this->sessions->pollLock($userId);
        $owner = $lock->acquire();
        if (!is_string($owner)) {
            return $owner;
        }

        try {
            $session = $this->sessions->beginPoll($userId, $sessionId);
            if (!is_array($session)) {
                return $session;
            }

            $poll = $this->client->pollDeviceAuthorization(
                $this->stringValue($session['device_auth_id'] ?? null),
                $this->stringValue($session['user_code'] ?? null)
            );
            if (!is_array($poll)) {
                $retryable = $this->retryablePollResult($poll, $sessionId, $session);
                if (is_array($retryable)) {
                    return $retryable;
                }
                $this->sessions->markError($userId, $sessionId, OAuthError::code($poll));

                return $poll;
            }

            if (($poll['status'] ?? '') === 'pending') {
                return [
                    'status' => 'pending',
                    'session_id' => $sessionId,
                    'retry_after' => $this->integerValue($session['interval'] ?? null, 5),
                    'expires_at' => $this->integerValue($session['expires_at'] ?? null),
                ];
            }

            if (($poll['status'] ?? '') !== 'authorized') {
                $error = OAuthError::create(
                    'oauth_device_poll_response_invalid',
                    'OpenAI returned an unexpected device authorization status.',
                    502
                );
                $this->sessions->markError($userId, $sessionId, OAuthError::code($error));

                return $error;
            }

            return $this->completeApproval($userId, $sessionId, $session, $poll);
        } finally {
            $lock->release($owner);
        }
    }

    /**
     * Cancels the current user's matching device authorization session.
     *
     * @since 1.1.0
     *
     * @return array<string, mixed>|object Safe status or WP_Error.
     */
    public function cancel(int $userId, string $sessionId)
    {
        $cancelled = $this->sessions->cancel($userId, $sessionId);
        if ($cancelled !== true) {
            return $cancelled;
        }

        return [
            'status' => 'cancelled',
            'session_id' => $sessionId,
        ];
    }

    /**
     * Deletes site-wide OAuth credentials and resets to API-key mode.
     *
     * @since 1.1.0
     *
     * @return array<string, mixed>|object Safe status or WP_Error.
     */
    public function disconnect(int $userId)
    {
        $this->sessions->cancelCurrent($userId);

        $lock = $this->tokenManager->credentialLock();
        $owner = $lock->acquire();
        if (!is_string($owner)) {
            return $owner;
        }

        try {
            $reset = $this->mode->resetToApiKey();
            if ($reset !== true) {
                return $reset;
            }

            $deleted = $this->tokenManager->deleteTokenSet();
            if ($deleted !== true) {
                return $deleted;
            }

            return [
                'disconnected' => true,
                'mode' => AuthenticationMode::MODE_API_KEY,
                'has_api_key' => $this->mode->hasApiKey(),
            ];
        } finally {
            $lock->release($owner);
        }
    }

    /**
     * Selects a mode and returns the resulting token-free status.
     *
     * @since 1.1.0
     *
     * @return array<string, mixed>|object Status or WP_Error.
     */
    public function setMode(int $userId, string $mode)
    {
        $lock = $this->tokenManager->credentialLock();
        $owner = $lock->acquire();
        if (!is_string($owner)) {
            return $owner;
        }

        try {
            $selected = $this->mode->set($mode);
            if ($selected !== true) {
                return $selected;
            }

            return $this->status($userId);
        } finally {
            $lock->release($owner);
        }
    }

    /**
     * Returns token-free site and current-user authentication status.
     *
     * @since 1.1.0
     *
     * @return array<string, mixed> Token-free status.
     */
    public function status(int $userId)
    {
        $tokens = $this->tokenManager->getStoredTokenSet();
        $oauthErrorCode = '';
        $oauthErrorMessage = '';
        if (is_object($tokens)) {
            $oauthErrorCode = OAuthError::code($tokens);
            $oauthErrorMessage = OAuthError::message($tokens);
            $tokens = null;
        }

        $connected = is_array($tokens);
        $expiresAt = $connected ? $this->integerValue($tokens['expires_at'] ?? null) : null;
        $needsRefresh = $connected ? $this->tokenManager->needsRefresh($tokens) : false;

        return [
            'mode' => $this->mode->get(),
            'has_api_key' => $this->mode->hasApiKey(),
            'api_key_source' => $this->mode->apiKeySource(),
            'oauth_connected' => $connected,
            'oauth_expires_at' => $expiresAt,
            'oauth_needs_refresh' => $needsRefresh,
            'oauth_account_label' => $connected && isset($tokens['account_label'])
                && is_string($tokens['account_label'])
                ? $tokens['account_label']
                : '',
            'oauth_error_code' => $oauthErrorCode,
            'oauth_error_message' => $oauthErrorMessage,
            'encryption_available' => $this->tokenStore->isEncryptionAvailable(),
            'session' => $this->sessions->getSafeStatus($userId),
        ];
    }

    /**
     * Converts retryable upstream polling failures to a successful pending state.
     *
     * @param mixed                $error     Possible WP_Error.
     * @param string               $sessionId Public session ID.
     * @param array<string, mixed> $session   Internal session.
     * @return array<string, mixed>|null
     */
    private function retryablePollResult($error, string $sessionId, array $session): ?array
    {
        $code = OAuthError::code($error);
        if (!in_array($code, ['oauth_http_request_failed', 'oauth_rate_limited'], true)) {
            return null;
        }

        $data = OAuthError::data($error);
        $retryAfter = isset($data['retry_after']) && is_numeric($data['retry_after'])
            ? $this->integerValue($data['retry_after'])
            : (isset($session['interval']) && is_numeric($session['interval'])
                ? $this->integerValue($session['interval'])
                : 5);

        return [
            'status' => 'pending',
            'session_id' => $sessionId,
            'retry_after' => max(1, min(300, $retryAfter)),
            'expires_at' => isset($session['expires_at']) && is_numeric($session['expires_at'])
                ? $this->integerValue($session['expires_at'])
                : time() + OAuthSessionStore::SESSION_TTL,
            'message' => OAuthError::message($error),
        ];
    }

    /**
     * Exchanges and stores an approval while holding the site-wide credential lock.
     *
     * @param array<string, mixed> $session Internal device session.
     * @param array<string, mixed> $poll    Authorized poll response.
     * @return array<string, mixed>|object Safe result or WP_Error.
     */
    private function completeApproval(int $userId, string $sessionId, array $session, array $poll)
    {
        $lock = $this->tokenManager->credentialLock();
        $owner = $lock->acquire();
        if (!is_string($owner)) {
            $data = OAuthError::data($owner);

            return [
                'status' => 'pending',
                'session_id' => $sessionId,
                'retry_after' => isset($data['retry_after']) && is_numeric($data['retry_after'])
                    ? $this->integerValue($data['retry_after'])
                    : 1,
                'expires_at' => $this->integerValue($session['expires_at'] ?? null),
                'message' => 'Waiting for another credential update to finish.',
            ];
        }

        try {
            $previousTokens = $this->tokenManager->getStoredTokenSet();
            if (is_object($previousTokens)) {
                return $previousTokens;
            }
            $previousMode = $this->mode->get();

            // Cancellation and ownership check before consuming the approval.
            $active = $this->sessions->assertActive($userId, $sessionId, ['pending']);
            if (!is_array($active)) {
                return $active;
            }

            $exchanging = $this->sessions->markExchanging($userId, $sessionId);
            if ($exchanging !== true) {
                return $exchanging;
            }

            $active = $this->sessions->assertActive($userId, $sessionId, ['exchanging']);
            if (!is_array($active)) {
                return $active;
            }

            $tokens = $this->client->exchangeAuthorizationCode(
                $this->stringValue($poll['authorization_code'] ?? null),
                $this->stringValue($poll['code_verifier'] ?? null)
            );
            if (!is_array($tokens)) {
                $retryable = $this->retryablePollResult($tokens, $sessionId, $session);
                if (is_array($retryable)) {
                    $this->sessions->markPending($userId, $sessionId);

                    return $retryable;
                }
                $this->sessions->markError($userId, $sessionId, OAuthError::code($tokens));

                return $tokens;
            }

            // Re-read the per-user cancellation marker immediately before save.
            $active = $this->sessions->assertActive($userId, $sessionId, ['exchanging']);
            if (!is_array($active)) {
                return $active;
            }

            $saved = $this->tokenManager->storeTokenSet($tokens);
            if ($saved !== true) {
                $this->sessions->markError($userId, $sessionId, OAuthError::code($saved));

                return $saved;
            }

            // Roll back if cancellation raced with the encrypted write.
            $active = $this->sessions->assertActive($userId, $sessionId, ['exchanging']);
            if (!is_array($active)) {
                $this->restoreCredentials($previousTokens, $previousMode);

                return $active;
            }

            // OAuth only becomes active after a complete exchange and encrypted save.
            $selected = $this->mode->set(AuthenticationMode::MODE_OAUTH);
            if ($selected !== true) {
                $this->restoreCredentials($previousTokens, $previousMode);
                $this->sessions->markError($userId, $sessionId, OAuthError::code($selected));

                return $selected;
            }

            $active = $this->sessions->assertActive($userId, $sessionId, ['exchanging']);
            if (!is_array($active)) {
                $this->restoreCredentials($previousTokens, $previousMode);

                return $active;
            }

            $approved = $this->sessions->markApproved($userId, $sessionId);
            if ($approved !== true) {
                $this->restoreCredentials($previousTokens, $previousMode);

                return $approved;
            }

            return [
                'status' => 'approved',
                'session_id' => $sessionId,
                'mode' => AuthenticationMode::MODE_OAUTH,
                'connected' => true,
            ];
        } finally {
            $lock->release($owner);
        }
    }

    /**
     * Restores credentials and mode after a cancelled or failed finalization.
     *
     * @param array<string, mixed>|null $previousTokens Previous encrypted token data.
     */
    private function restoreCredentials(?array $previousTokens, string $previousMode): void
    {
        if (is_array($previousTokens)) {
            $restored = $this->tokenManager->storeTokenSet($previousTokens);
            if ($restored === true && $previousMode === AuthenticationMode::MODE_OAUTH) {
                $this->mode->set(AuthenticationMode::MODE_OAUTH);

                return;
            }
        }

        $this->mode->resetToApiKey();
        if (!is_array($previousTokens)) {
            $this->tokenManager->deleteTokenSet();
        }
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
}
