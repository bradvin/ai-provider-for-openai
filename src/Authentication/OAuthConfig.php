<?php

declare(strict_types=1);

namespace WordPress\OpenAiAiProvider\Authentication;

/**
 * Centralized, safety-checked OpenAI Codex OAuth configuration.
 *
 * The device-code flow authenticates a ChatGPT/Codex subscription. It does not
 * mint a platform.openai.com API key, and its token is intended for the Codex
 * backend endpoint rather than api.openai.com.
 *
 * @since 1.1.0
 */
final class OAuthConfig
{
    public const CLIENT_ID = 'app_EMoamEEZ73f0CkXaXp7hrann';
    public const DEVICE_START_URL = 'https://auth.openai.com/api/accounts/deviceauth/usercode';
    public const DEVICE_POLL_URL = 'https://auth.openai.com/api/accounts/deviceauth/token';
    public const TOKEN_URL = 'https://auth.openai.com/oauth/token';
    public const VERIFICATION_URL = 'https://auth.openai.com/codex/device';
    public const REDIRECT_URL = 'https://auth.openai.com/deviceauth/callback';
    public const CODEX_API_BASE_URL = 'https://chatgpt.com/backend-api/codex';

    /**
     * Returns the OAuth client ID after validating any filter override.
     *
     * @since 1.1.0
     */
    public static function clientId(): string
    {
        $candidate = self::applyFilter('ai_provider_for_openai_oauth_client_id', self::CLIENT_ID);

        if (
            is_string($candidate)
            && strlen($candidate) <= 200
            && preg_match('/\A[A-Za-z0-9._-]+\z/', $candidate) === 1
        ) {
            return $candidate;
        }

        return self::CLIENT_ID;
    }

    /**
     * Returns the device authorization start endpoint.
     *
     * @since 1.1.0
     */
    public static function deviceStartUrl(): string
    {
        return self::filteredAuthUrl(
            'ai_provider_for_openai_oauth_device_start_url',
            self::DEVICE_START_URL,
            '/api/accounts/deviceauth/usercode'
        );
    }

    /**
     * Returns the device authorization polling endpoint.
     *
     * @since 1.1.0
     */
    public static function devicePollUrl(): string
    {
        return self::filteredAuthUrl(
            'ai_provider_for_openai_oauth_device_poll_url',
            self::DEVICE_POLL_URL,
            '/api/accounts/deviceauth/token'
        );
    }

    /**
     * Returns the OAuth token endpoint.
     *
     * @since 1.1.0
     */
    public static function tokenUrl(): string
    {
        return self::filteredAuthUrl(
            'ai_provider_for_openai_oauth_token_url',
            self::TOKEN_URL,
            '/oauth/token'
        );
    }

    /**
     * Returns the fixed OAuth redirect URI.
     *
     * @since 1.1.0
     */
    public static function redirectUrl(): string
    {
        return self::filteredAuthUrl(
            'ai_provider_for_openai_oauth_redirect_url',
            self::REDIRECT_URL,
            '/deviceauth/callback'
        );
    }

    /**
     * Returns an allowlisted verification URL suitable for opening in a tab.
     *
     * @since 1.1.0
     *
     * @param mixed $candidate URL supplied by the authorization server.
     */
    public static function verificationUrl($candidate = ''): string
    {
        if (is_string($candidate) && self::isAllowedVerificationUrl($candidate)) {
            return $candidate;
        }

        $filtered = self::applyFilter(
            'ai_provider_for_openai_oauth_verification_url',
            self::VERIFICATION_URL
        );

        if (is_string($filtered) && self::isAllowedVerificationUrl($filtered)) {
            return $filtered;
        }

        return self::VERIFICATION_URL;
    }

    /**
     * Returns the Codex subscription API base URL.
     *
     * @since 1.1.0
     */
    public static function codexApiBaseUrl(): string
    {
        $candidate = self::applyFilter(
            'ai_provider_for_openai_codex_api_base_url',
            self::CODEX_API_BASE_URL
        );

        if (is_string($candidate) && self::isAllowedCodexApiBaseUrl($candidate)) {
            return rtrim($candidate, '/');
        }

        return self::CODEX_API_BASE_URL;
    }

    /**
     * Checks whether a URL is safe to expose as the OpenAI verification URL.
     *
     * @since 1.1.0
     */
    public static function isAllowedVerificationUrl(string $url): bool
    {
        return self::isSafeHttpsUrl($url, 'auth.openai.com', '/codex/device', true);
    }

    /**
     * Checks whether a URL is the allowlisted Codex backend base URL.
     *
     * @since 1.1.0
     */
    public static function isAllowedCodexApiBaseUrl(string $url): bool
    {
        return self::isSafeHttpsUrl(
            rtrim($url, '/'),
            'chatgpt.com',
            '/backend-api/codex',
            false
        );
    }

    /**
     * Checks whether a request URL is inside the configured Codex API base.
     *
     * This validator is intended for the final request immediately before
     * bearer credentials are attached. Query parameters are allowed, but URL
     * credentials, ports, fragments, encoded paths, and traversal segments are
     * rejected.
     *
     * @since 1.1.0
     *
     * @param string $url The final request URL.
     * @return bool True when the URL is safe for Codex bearer credentials.
     */
    public static function isAllowedCodexApiRequestUrl(string $url): bool
    {
        if (preg_match('/[\x00-\x20\x7f]/', $url) === 1) {
            return false;
        }

        $parts = parse_url($url);
        $baseParts = parse_url(self::codexApiBaseUrl());
        if (!is_array($parts) || !is_array($baseParts)) {
            return false;
        }

        if (
            strtolower((string) ($parts['scheme'] ?? '')) !== 'https'
            || strtolower((string) ($parts['host'] ?? '')) !== 'chatgpt.com'
            || isset($parts['port'])
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['fragment'])
        ) {
            return false;
        }

        $path = (string) ($parts['path'] ?? '');
        $basePath = rtrim((string) ($baseParts['path'] ?? ''), '/');
        if (
            $path === ''
            || $basePath === ''
            || strpos($path, '%') !== false
            || strpos($path, '\\') !== false
        ) {
            return false;
        }

        foreach (explode('/', $path) as $segment) {
            if ($segment === '.' || $segment === '..') {
                return false;
            }
        }

        return $path === $basePath || strpos($path, $basePath . '/') === 0;
    }

    /**
     * Applies a WordPress filter when available.
     *
     * @param string $name  Filter name.
     * @param mixed  $value Default value.
     * @return mixed Filtered value.
     */
    private static function applyFilter(string $name, $value)
    {
        if (!function_exists('apply_filters')) {
            return $value;
        }

        return apply_filters($name, $value);
    }

    /**
     * Returns a safety-checked auth.openai.com endpoint override.
     */
    private static function filteredAuthUrl(string $filter, string $default, string $path): string
    {
        $candidate = self::applyFilter($filter, $default);

        if (
            is_string($candidate)
            && self::isSafeHttpsUrl($candidate, 'auth.openai.com', $path, false)
        ) {
            return $candidate;
        }

        return $default;
    }

    /**
     * Validates a fixed-host HTTPS URL without credentials, fragments, or ports.
     */
    private static function isSafeHttpsUrl(
        string $url,
        string $allowedHost,
        string $allowedPath,
        bool $allowQuery
    ): bool {
        $parts = parse_url($url);
        if (!is_array($parts)) {
            return false;
        }

        if (
            strtolower((string) ($parts['scheme'] ?? '')) !== 'https'
            || strtolower((string) ($parts['host'] ?? '')) !== $allowedHost
            || (string) ($parts['path'] ?? '') !== $allowedPath
            || isset($parts['port'])
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['fragment'])
        ) {
            return false;
        }

        return $allowQuery || !isset($parts['query']);
    }
}
