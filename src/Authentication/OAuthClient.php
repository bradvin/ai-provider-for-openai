<?php

declare(strict_types=1);

namespace WordPress\OpenAiAiProvider\Authentication;

/**
 * WordPress HTTP client for OpenAI's Codex device authorization flow.
 *
 * @since 1.1.0
 */
final class OAuthClient
{
    private const HTTP_TIMEOUT = 15;
    private const SESSION_TTL = 900;
    private const MIN_POLL_INTERVAL = 3;
    private const MAX_POLL_INTERVAL = 30;
    private const DEFAULT_ACCESS_TOKEN_TTL = 3600;

    /**
     * Starts device authorization.
     *
     * @since 1.1.0
     *
     * @return array<string, mixed>|object Device data or WP_Error.
     */
    public function startDeviceAuthorization()
    {
        $response = $this->postJson(
            OAuthConfig::deviceStartUrl(),
            ['client_id' => OAuthConfig::clientId()]
        );
        if (!is_array($response)) {
            return $response;
        }

        $status = $this->integerValue($response['status'] ?? null);
        if ($status === 429) {
            return $this->rateLimitError($response, 'OpenAI is temporarily rate-limiting login requests.');
        }
        if ($status !== 200) {
            return OAuthError::create(
                'oauth_device_start_failed',
                'OpenAI rejected the device authorization request.',
                502,
                ['upstream_status' => $status]
            );
        }

        $payload = $this->decodeJsonResponse($response);
        if (!is_array($payload)) {
            return $payload;
        }

        $userCode = $this->boundedString($payload['user_code'] ?? null, 128);
        $deviceAuthId = $this->boundedString($payload['device_auth_id'] ?? null, 1024);
        if ($userCode === '' || $deviceAuthId === '') {
            return OAuthError::create(
                'oauth_device_response_invalid',
                'OpenAI returned an incomplete device authorization response.',
                502
            );
        }

        $interval = $this->integerValue($payload['interval'] ?? null, 5);
        $interval = max(self::MIN_POLL_INTERVAL, min(self::MAX_POLL_INTERVAL, $interval));

        $verificationCandidate = $payload['verification_uri_complete']
            ?? $payload['verification_uri']
            ?? $payload['verification_url']
            ?? '';

        return [
            'device_auth_id' => $deviceAuthId,
            'user_code' => $userCode,
            'verification_url' => OAuthConfig::verificationUrl($verificationCandidate),
            'interval' => $interval,
            'expires_in' => self::SESSION_TTL,
        ];
    }

    /**
     * Polls the device endpoint once.
     *
     * @since 1.1.0
     *
     * @return array<string, mixed>|object Poll result or WP_Error.
     */
    public function pollDeviceAuthorization(string $deviceAuthId, string $userCode)
    {
        if ($deviceAuthId === '' || $userCode === '') {
            return OAuthError::create(
                'oauth_device_session_invalid',
                'The device authorization session is incomplete.',
                400
            );
        }

        $response = $this->postJson(
            OAuthConfig::devicePollUrl(),
            [
                'device_auth_id' => $deviceAuthId,
                'user_code' => $userCode,
            ]
        );
        if (!is_array($response)) {
            return $response;
        }

        $status = $this->integerValue($response['status'] ?? null);
        if (in_array($status, [202, 403, 404], true)) {
            return ['status' => 'pending'];
        }
        if ($status === 429) {
            return $this->rateLimitError($response, 'OpenAI is temporarily rate-limiting login polling.');
        }
        if ($status !== 200) {
            return OAuthError::create(
                'oauth_device_poll_failed',
                'OpenAI rejected the device authorization poll.',
                502,
                ['upstream_status' => $status]
            );
        }

        $payload = $this->decodeJsonResponse($response);
        if (!is_array($payload)) {
            return $payload;
        }

        $authorizationCode = $this->boundedString($payload['authorization_code'] ?? null, 4096);
        $codeVerifier = $this->boundedString($payload['code_verifier'] ?? null, 4096);
        if ($authorizationCode === '' || $codeVerifier === '') {
            return OAuthError::create(
                'oauth_device_poll_response_invalid',
                'OpenAI returned an incomplete authorization approval.',
                502
            );
        }

        return [
            'status' => 'authorized',
            'authorization_code' => $authorizationCode,
            'code_verifier' => $codeVerifier,
        ];
    }

    /**
     * Exchanges the approved device authorization code for OAuth tokens.
     *
     * @since 1.1.0
     *
     * @return array<string, mixed>|object Token set or WP_Error.
     */
    public function exchangeAuthorizationCode(string $authorizationCode, string $codeVerifier)
    {
        if ($authorizationCode === '' || $codeVerifier === '') {
            return OAuthError::create(
                'oauth_exchange_input_invalid',
                'The authorization approval is incomplete.',
                400
            );
        }

        $response = $this->postForm(
            OAuthConfig::tokenUrl(),
            [
                'grant_type' => 'authorization_code',
                'code' => $authorizationCode,
                'redirect_uri' => OAuthConfig::redirectUrl(),
                'client_id' => OAuthConfig::clientId(),
                'code_verifier' => $codeVerifier,
            ]
        );
        if (!is_array($response)) {
            return $response;
        }

        $status = $this->integerValue($response['status'] ?? null);
        if ($status === 429) {
            return $this->rateLimitError($response, 'OpenAI is temporarily rate-limiting token exchange.');
        }
        if ($status !== 200) {
            return OAuthError::create(
                'oauth_token_exchange_failed',
                'OpenAI rejected the OAuth token exchange.',
                502,
                ['upstream_status' => $status]
            );
        }

        $payload = $this->decodeJsonResponse($response);
        if (!is_array($payload)) {
            return $payload;
        }

        return $this->tokenSetFromPayload($payload);
    }

    /**
     * Refreshes an OAuth token and preserves the old refresh token when the
     * response does not rotate it.
     *
     * @since 1.1.0
     *
     * @return array<string, mixed>|object Token set or WP_Error.
     */
    public function refreshTokens(string $refreshToken)
    {
        if ($refreshToken === '') {
            return OAuthError::create(
                'oauth_refresh_token_missing',
                'The OAuth credentials do not contain a refresh token.',
                401,
                ['reconnect_required' => true]
            );
        }

        $response = $this->postForm(
            OAuthConfig::tokenUrl(),
            [
                'grant_type' => 'refresh_token',
                'refresh_token' => $refreshToken,
                'client_id' => OAuthConfig::clientId(),
            ]
        );
        if (!is_array($response)) {
            return $response;
        }

        $status = $this->integerValue($response['status'] ?? null);
        if ($status === 429) {
            return $this->rateLimitError($response, 'OpenAI is temporarily rate-limiting token refresh.');
        }
        if ($status !== 200) {
            return OAuthError::create(
                'oauth_token_refresh_failed',
                'OpenAI rejected the OAuth token refresh.',
                $status === 400 || $status === 401 || $status === 403 ? 401 : 502,
                [
                    'upstream_status' => $status,
                    'reconnect_required' => in_array($status, [400, 401, 403], true),
                ]
            );
        }

        $payload = $this->decodeJsonResponse($response);
        if (!is_array($payload)) {
            return $payload;
        }

        return $this->tokenSetFromPayload($payload, $refreshToken);
    }

    /**
     * Normalizes a token endpoint payload into the encrypted-store shape.
     *
     * This method is public to support pure unit tests without HTTP calls.
     *
     * @since 1.1.0
     *
     * @param array<string, mixed> $payload              Token endpoint payload.
     * @param string               $existingRefreshToken Existing token to preserve when not rotated.
     * @return array<string, mixed>|object Token set or WP_Error.
     */
    public function tokenSetFromPayload(array $payload, string $existingRefreshToken = '')
    {
        $accessToken = $this->boundedString($payload['access_token'] ?? null, 32768);
        $refreshToken = $this->boundedString($payload['refresh_token'] ?? null, 32768);
        if ($refreshToken === '') {
            $refreshToken = $existingRefreshToken;
        }

        if ($accessToken === '' || $refreshToken === '') {
            return OAuthError::create(
                'oauth_token_response_invalid',
                'OpenAI did not return a usable access and refresh token pair.',
                502
            );
        }

        $claims = self::decodeJwtClaims($accessToken);
        $expiresAt = time() + self::DEFAULT_ACCESS_TOKEN_TTL;
        if (isset($payload['expires_in']) && is_numeric($payload['expires_in'])) {
            $expiresAt = time() + max(60, (int) $payload['expires_in']);
        }
        if (isset($claims['exp']) && is_numeric($claims['exp']) && (int) $claims['exp'] > 0) {
            $expiresAt = (int) $claims['exp'];
        }

        $accountId = '';
        $authClaims = $claims['https://api.openai.com/auth'] ?? null;
        if (is_array($authClaims) && isset($authClaims['chatgpt_account_id'])) {
            $accountId = $this->boundedString($authClaims['chatgpt_account_id'], 512);
        }

        $accountLabel = '';
        $profileClaims = $claims['https://api.openai.com/profile'] ?? null;
        if (is_array($profileClaims) && isset($profileClaims['email'])) {
            $accountLabel = $this->boundedString($profileClaims['email'], 320);
        }
        if ($accountLabel === '' && isset($claims['email'])) {
            $accountLabel = $this->boundedString($claims['email'], 320);
        }
        if ($accountLabel === '') {
            $accountLabel = 'OpenAI account';
        }

        return [
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
            'token_type' => $this->boundedString($payload['token_type'] ?? 'Bearer', 64) ?: 'Bearer',
            'expires_at' => $expiresAt,
            'obtained_at' => time(),
            'account_id' => $accountId,
            'account_label' => $accountLabel,
        ];
    }

    /**
     * Decodes JWT claims without treating them as trusted authorization data.
     *
     * The values are used only for expiry scheduling and an OpenAI routing header.
     *
     * @since 1.1.0
     *
     * @return array<string, mixed>
     */
    public static function decodeJwtClaims(string $token): array
    {
        $parts = explode('.', $token);
        if (count($parts) < 2) {
            return [];
        }

        $encoded = strtr($parts[1], '-_', '+/');
        $remainder = strlen($encoded) % 4;
        if ($remainder > 0) {
            $encoded .= str_repeat('=', 4 - $remainder);
        }

        $decoded = base64_decode($encoded, true);
        if (!is_string($decoded)) {
            return [];
        }

        $claims = json_decode($decoded, true);

        if (!is_array($claims)) {
            return [];
        }

        /** @var array<string, mixed> $claims */
        return $claims;
    }

    /**
     * Performs a safe JSON POST.
     *
     * @param array<string, string> $body Request body.
     * @return array<string, mixed>|object Response summary or WP_Error.
     */
    private function postJson(string $url, array $body)
    {
        $encoded = $this->encodeJson($body);
        if (!is_string($encoded)) {
            return OAuthError::create(
                'oauth_request_encoding_failed',
                'The OAuth request could not be encoded.',
                500
            );
        }

        return $this->post(
            $url,
            [
                'headers' => [
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/json',
                ],
                'body' => $encoded,
            ]
        );
    }

    /**
     * Performs a safe form-encoded POST.
     *
     * @param array<string, string> $body Request body.
     * @return array<string, mixed>|object Response summary or WP_Error.
     */
    private function postForm(string $url, array $body)
    {
        return $this->post(
            $url,
            [
                'headers' => [
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ],
                'body' => http_build_query($body, '', '&', PHP_QUERY_RFC3986),
            ]
        );
    }

    /**
     * Performs a safe WordPress HTTP POST and returns only required metadata.
     *
     * @param array<string, mixed> $args Request arguments.
     * @return array<string, mixed>|object Response summary or WP_Error.
     */
    private function post(string $url, array $args)
    {
        if (
            !function_exists('wp_safe_remote_post')
            || !function_exists('wp_remote_retrieve_response_code')
            || !function_exists('wp_remote_retrieve_body')
        ) {
            return OAuthError::create(
                'oauth_http_unavailable',
                'The WordPress HTTP API is unavailable.',
                500
            );
        }

        $args['timeout'] = self::HTTP_TIMEOUT;
        $args['redirection'] = 0;
        $response = wp_safe_remote_post($url, $args);
        if (OAuthError::is($response)) {
            return OAuthError::create(
                'oauth_http_request_failed',
                'The OAuth server could not be reached.',
                502
            );
        }

        $retryAfter = '';
        if (function_exists('wp_remote_retrieve_header')) {
            $header = wp_remote_retrieve_header($response, 'retry-after');
            if (is_string($header)) {
                $retryAfter = $header;
            }
        }

        return [
            'status' => $this->integerValue(wp_remote_retrieve_response_code($response)),
            'body' => $this->stringValue(wp_remote_retrieve_body($response)),
            'retry_after' => $retryAfter,
        ];
    }

    /**
     * Decodes a successful JSON response.
     *
     * @param array<string, mixed> $response Response summary.
     * @return array<string, mixed>|object Decoded response or WP_Error.
     */
    private function decodeJsonResponse(array $response)
    {
        $payload = json_decode($this->stringValue($response['body'] ?? null), true);
        if (!is_array($payload)) {
            return OAuthError::create(
                'oauth_response_invalid_json',
                'OpenAI returned an invalid OAuth response.',
                502
            );
        }

        /** @var array<string, mixed> $payload */
        return $payload;
    }

    /**
     * Creates a rate-limit error with a bounded Retry-After value.
     *
     * @param array<string, mixed> $response Response summary.
     */
    private function rateLimitError(array $response, string $message): object
    {
        $retryAfter = 60;
        if (isset($response['retry_after']) && is_numeric($response['retry_after'])) {
            $retryAfter = max(1, min(300, $this->integerValue($response['retry_after'])));
        }

        return OAuthError::create(
            'oauth_rate_limited',
            $message,
            429,
            ['retry_after' => $retryAfter]
        );
    }

    /**
     * Encodes JSON with the WordPress encoder when available.
     *
     * @param array<string, string> $data Data to encode.
     * @return string|false
     */
    private function encodeJson(array $data)
    {
        if (function_exists('wp_json_encode')) {
            $encoded = wp_json_encode($data);

            return is_string($encoded) ? $encoded : false;
        }

        return json_encode($data);
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
}
