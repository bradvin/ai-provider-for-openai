<?php

declare(strict_types=1);

namespace WordPress\OpenAiAiProvider\Authentication;

use WordPress\AiClient\Common\Exception\RuntimeException;

/**
 * Provides current OAuth credentials and refreshes them under a short lock.
 *
 * @since 1.1.0
 */
final class OAuthTokenManager
{
    private const REFRESH_LOCK_OPTION = '_ai_provider_for_openai_oauth_refresh_lock';
    private const REFRESH_LOCK_TTL = 30;
    private const REFRESH_SKEW = 120;

    /** @var EncryptedTokenStore */
    private $tokenStore;

    /** @var OAuthClient */
    private $client;

    /**
     * @since 1.1.0
     */
    public function __construct(?EncryptedTokenStore $tokenStore = null, ?OAuthClient $client = null)
    {
        $this->tokenStore = $tokenStore ?? new EncryptedTokenStore();
        $this->client = $client ?? new OAuthClient();
    }

    /**
     * Gets a current OAuth access token for request authentication.
     *
     * @since 1.1.0
     *
     * @throws RuntimeException When credentials are absent or cannot be refreshed.
     */
    public function getAccessToken(): string
    {
        $tokens = $this->getTokenSet();
        if (!is_array($tokens)) {
            $code = OAuthError::code($tokens);
            $message = OAuthError::message($tokens);
            if ($message === '') {
                $message = 'OpenAI OAuth credentials are unavailable.';
            }
            if ($code !== '') {
                $message .= ' (' . $code . ')';
            }

            throw new RuntimeException($message);
        }

        $accessToken = $tokens['access_token'] ?? null;
        if (!is_string($accessToken) || $accessToken === '') {
            throw new RuntimeException('OpenAI OAuth credentials do not contain an access token.');
        }

        return $accessToken;
    }

    /**
     * Gets a fresh internal token set.
     *
     * @since 1.1.0
     *
     * @return array<string, mixed>|object Token set or WP_Error.
     */
    public function getTokenSet()
    {
        $tokens = $this->tokenStore->getTokens();
        if (is_object($tokens)) {
            return $tokens;
        }
        if (!is_array($tokens)) {
            return OAuthError::create(
                'oauth_credentials_missing',
                'Connect an OpenAI account before using OAuth.',
                401,
                ['reconnect_required' => true]
            );
        }

        if (!$this->needsRefresh($tokens)) {
            return $tokens;
        }

        return $this->refreshTokens();
    }

    /**
     * Gets stored token metadata without triggering refresh.
     *
     * @since 1.1.0
     *
     * @return array<string, mixed>|object|null Token set, WP_Error, or null.
     */
    public function getStoredTokenSet()
    {
        return $this->tokenStore->getTokens();
    }

    /**
     * Stores an exchanged token pair and notifies provider integrations.
     *
     * @since 1.1.0
     *
     * @param array<string, mixed> $tokens Token data.
     * @return true|object True or WP_Error.
     */
    public function storeTokenSet(array $tokens)
    {
        $saved = $this->tokenStore->saveTokens($tokens);
        if ($saved !== true) {
            return $saved;
        }

        $this->notifyAuthenticationChanged();

        return true;
    }

    /**
     * Deletes stored tokens and notifies provider integrations.
     *
     * Callers that coordinate connection state should hold credentialLock().
     *
     * @since 1.1.0
     *
     * @return true|object True or WP_Error.
     */
    public function deleteTokenSet()
    {
        $deleted = $this->tokenStore->deleteTokens();
        if ($deleted !== true) {
            return $deleted;
        }

        $this->notifyAuthenticationChanged();

        return true;
    }

    /**
     * Creates the site-wide lock shared by refresh, approval, and disconnect.
     *
     * @since 1.1.0
     */
    public function credentialLock(): OptionLock
    {
        return new OptionLock(self::REFRESH_LOCK_OPTION, self::REFRESH_LOCK_TTL);
    }

    /**
     * Determines whether a token should be refreshed before use.
     *
     * This method is public to support pure expiry unit tests.
     *
     * @since 1.1.0
     *
     * @param array<string, mixed> $tokens Token data.
     */
    public function needsRefresh(array $tokens): bool
    {
        if (!isset($tokens['expires_at']) || !is_numeric($tokens['expires_at'])) {
            return true;
        }

        return (int) $tokens['expires_at'] <= time() + self::REFRESH_SKEW;
    }

    /**
     * Refreshes and atomically replaces the stored token pair.
     *
     * @return array<string, mixed>|object Token set or WP_Error.
     */
    private function refreshTokens()
    {
        $lock = $this->credentialLock();
        $owner = $lock->acquire();
        if (!is_string($owner)) {
            return $this->readDuringRefreshContention($owner);
        }

        try {
            $tokens = $this->tokenStore->getTokens();
            if (is_object($tokens)) {
                return $tokens;
            }
            if (!is_array($tokens)) {
                return OAuthError::create(
                    'oauth_credentials_missing',
                    'Connect an OpenAI account before using OAuth.',
                    401,
                    ['reconnect_required' => true]
                );
            }

            // Another request may have refreshed while this request waited for the lock.
            if (!$this->needsRefresh($tokens)) {
                return $tokens;
            }

            $refreshToken = $tokens['refresh_token'] ?? null;
            if (!is_string($refreshToken) || $refreshToken === '') {
                return OAuthError::create(
                    'oauth_refresh_token_missing',
                    'The OAuth credentials do not contain a refresh token.',
                    401,
                    ['reconnect_required' => true]
                );
            }

            $refreshed = $this->client->refreshTokens($refreshToken);
            if (!is_array($refreshed)) {
                if ($this->canUseExistingTokenAfterRefreshFailure($tokens, $refreshed)) {
                    return $tokens;
                }

                return $refreshed;
            }

            $saved = $this->tokenStore->saveTokens($refreshed);
            if ($saved !== true) {
                return $saved;
            }

            $this->notifyAuthenticationChanged();

            return $refreshed;
        } finally {
            $lock->release($owner);
        }
    }

    /**
     * Uses a still-valid token during refresh contention, then performs a few
     * bounded re-reads for a concurrently refreshed replacement.
     *
     * @param object $lockError Lock contention WP_Error.
     * @return array<string, mixed>|object Token set or the original WP_Error.
     */
    private function readDuringRefreshContention(object $lockError)
    {
        for ($attempt = 0; $attempt < 64; $attempt++) {
            $tokens = $this->tokenStore->getTokens();
            if (is_object($tokens)) {
                return $tokens;
            }
            if (
                is_array($tokens)
                && isset($tokens['access_token'], $tokens['expires_at'])
                && is_string($tokens['access_token'])
                && $tokens['access_token'] !== ''
                && is_numeric($tokens['expires_at'])
                && (int) $tokens['expires_at'] > time() + 5
            ) {
                return $tokens;
            }

            if ($attempt < 63) {
                usleep(250000);
            }
        }

        return $lockError;
    }

    /**
     * Keeps a still-valid access token usable after a transient refresh failure.
     *
     * @param array<string, mixed> $tokens Stored token data.
     * @param mixed                $error  Refresh error.
     */
    private function canUseExistingTokenAfterRefreshFailure(array $tokens, $error): bool
    {
        if (
            !isset($tokens['access_token'], $tokens['expires_at'])
            || !is_string($tokens['access_token'])
            || $tokens['access_token'] === ''
            || !is_numeric($tokens['expires_at'])
            || (int) $tokens['expires_at'] <= time() + 5
        ) {
            return false;
        }

        $code = OAuthError::code($error);
        if (
            in_array(
                $code,
                ['oauth_http_request_failed', 'oauth_rate_limited', 'oauth_response_invalid_json'],
                true
            )
        ) {
            return true;
        }

        if ($code !== 'oauth_token_refresh_failed') {
            return false;
        }

        $data = OAuthError::data($error);
        $upstreamStatus = isset($data['upstream_status']) && is_numeric($data['upstream_status'])
            ? (int) $data['upstream_status']
            : 0;

        return $upstreamStatus === 0 || $upstreamStatus >= 500;
    }

    /**
     * Notifies the provider that its authentication binding changed.
     */
    private function notifyAuthenticationChanged(): void
    {
        if (function_exists('do_action')) {
            do_action('ai_provider_for_openai_auth_changed');
        }
    }
}
