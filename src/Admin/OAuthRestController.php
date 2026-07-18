<?php

declare(strict_types=1);

namespace WordPress\OpenAiAiProvider\Admin;

use WordPress\OpenAiAiProvider\Authentication\AuthenticationMode;
use WordPress\OpenAiAiProvider\Authentication\OAuthError;
use WordPress\OpenAiAiProvider\Authentication\OAuthFlow;

/**
 * Registers manage_options-only REST endpoints for the OpenAI OAuth UI.
 *
 * Browser requests use WordPress cookie authentication and the normal
 * X-WP-Nonce header. Responses intentionally never contain OAuth tokens.
 *
 * @since 1.1.0
 */
final class OAuthRestController
{
    public const REST_NAMESPACE = 'ai-provider-for-openai/v1';

    /** @var OAuthFlow */
    private $flow;

    /**
     * @since 1.1.0
     */
    public function __construct(?OAuthFlow $flow = null)
    {
        $this->flow = $flow ?? new OAuthFlow();
    }

    /**
     * Hooks REST route registration.
     *
     * @since 1.1.0
     */
    public function register(): void
    {
        if (function_exists('add_action')) {
            add_action('rest_api_init', [$this, 'registerRoutes']);
        }
    }

    /**
     * Registers authentication status and mutation routes.
     *
     * @since 1.1.0
     */
    public function registerRoutes(): void
    {
        if (!function_exists('register_rest_route')) {
            return;
        }

        register_rest_route(
            self::REST_NAMESPACE,
            '/auth/status',
            [
                'methods' => 'GET',
                'callback' => [$this, 'getStatus'],
                'permission_callback' => [$this, 'checkPermission'],
            ]
        );
        register_rest_route(
            self::REST_NAMESPACE,
            '/auth/mode',
            [
                'methods' => 'POST',
                'callback' => [$this, 'setMode'],
                'permission_callback' => [$this, 'checkPermission'],
                'args' => [
                    'mode' => [
                        'type' => 'string',
                        'required' => true,
                        'enum' => [
                            AuthenticationMode::MODE_API_KEY,
                            AuthenticationMode::MODE_OAUTH,
                        ],
                        'sanitize_callback' => [$this, 'sanitizeMode'],
                        'validate_callback' => [$this, 'validateMode'],
                    ],
                ],
            ]
        );
        register_rest_route(
            self::REST_NAMESPACE,
            '/oauth/start',
            [
                'methods' => 'POST',
                'callback' => [$this, 'start'],
                'permission_callback' => [$this, 'checkPermission'],
            ]
        );
        register_rest_route(
            self::REST_NAMESPACE,
            '/oauth/poll',
            [
                'methods' => 'POST',
                'callback' => [$this, 'poll'],
                'permission_callback' => [$this, 'checkPermission'],
                'args' => $this->sessionIdArguments(),
            ]
        );
        register_rest_route(
            self::REST_NAMESPACE,
            '/oauth/cancel',
            [
                'methods' => 'POST',
                'callback' => [$this, 'cancel'],
                'permission_callback' => [$this, 'checkPermission'],
                'args' => $this->sessionIdArguments(),
            ]
        );
        register_rest_route(
            self::REST_NAMESPACE,
            '/oauth/connection',
            [
                'methods' => 'DELETE',
                'callback' => [$this, 'disconnect'],
                'permission_callback' => [$this, 'checkPermission'],
            ]
        );
    }

    /**
     * Requires an administrator-level settings capability.
     *
     * @since 1.1.0
     *
     * @return true|object True or WP_Error.
     */
    public function checkPermission()
    {
        if (function_exists('current_user_can') && current_user_can('manage_options')) {
            return true;
        }

        return OAuthError::create(
            'rest_forbidden',
            'You are not allowed to manage OpenAI authentication.',
            403
        );
    }

    /**
     * Returns current token-free authentication status.
     *
     * @since 1.1.0
     *
     * @param mixed $request REST request (unused).
     * @return mixed REST response or WP_Error.
     */
    public function getStatus($request = null)
    {
        unset($request);

        $status = $this->flow->status($this->currentUserId());

        return $this->respond($this->formatStatus($status));
    }

    /**
     * Updates the selected authentication mode.
     *
     * @since 1.1.0
     *
     * @param mixed $request REST request.
     * @return mixed REST response or WP_Error.
     */
    public function setMode($request)
    {
        $modeValue = $this->requestParameter($request, 'mode');
        $mode = is_string($modeValue) ? $modeValue : '';

        $status = $this->flow->setMode($this->currentUserId(), $mode);

        return $this->respond($this->formatStatus($status));
    }

    /**
     * Starts a per-user OAuth device authorization session.
     *
     * @since 1.1.0
     *
     * @param mixed $request REST request (unused).
     * @return mixed REST response or WP_Error.
     */
    public function start($request = null)
    {
        unset($request);

        $started = $this->flow->start($this->currentUserId());

        return $this->respond($this->formatStart($started));
    }

    /**
     * Polls a device authorization session once.
     *
     * @since 1.1.0
     *
     * @param mixed $request REST request.
     * @return mixed REST response or WP_Error.
     */
    public function poll($request)
    {
        $sessionIdValue = $this->requestParameter($request, 'sessionId');
        $sessionId = is_string($sessionIdValue) ? $sessionIdValue : '';

        $polled = $this->flow->poll($this->currentUserId(), $sessionId);

        return $this->respond($this->formatPoll($polled));
    }

    /**
     * Cancels a device authorization session.
     *
     * @since 1.1.0
     *
     * @param mixed $request REST request.
     * @return mixed REST response or WP_Error.
     */
    public function cancel($request)
    {
        $sessionIdValue = $this->requestParameter($request, 'sessionId');
        $sessionId = is_string($sessionIdValue) ? $sessionIdValue : '';

        return $this->respond($this->flow->cancel($this->currentUserId(), $sessionId));
    }

    /**
     * Disconnects the site's OAuth account.
     *
     * @since 1.1.0
     *
     * @param mixed $request REST request (unused).
     * @return mixed REST response or WP_Error.
     */
    public function disconnect($request = null)
    {
        unset($request);

        return $this->respond($this->flow->disconnect($this->currentUserId()));
    }

    /**
     * Validates a REST mode argument.
     *
     * @since 1.1.0
     *
     * @param mixed $value Value to validate.
     */
    public function validateMode($value): bool
    {
        return is_string($value)
            && in_array(
                $value,
                [AuthenticationMode::MODE_API_KEY, AuthenticationMode::MODE_OAUTH],
                true
            );
    }

    /**
     * Sanitizes a REST mode argument.
     *
     * @since 1.1.0
     *
     * @param mixed $value Value to sanitize.
     */
    public function sanitizeMode($value): string
    {
        return is_string($value) ? strtolower(trim($value)) : '';
    }

    /**
     * Validates a public session ID.
     *
     * @since 1.1.0
     *
     * @param mixed $value Value to validate.
     */
    public function validateSessionId($value): bool
    {
        return is_string($value) && preg_match('/\A[a-f0-9]{48}\z/', $value) === 1;
    }

    /**
     * Sanitizes a public session ID.
     *
     * @since 1.1.0
     *
     * @param mixed $value Value to sanitize.
     */
    public function sanitizeSessionId($value): string
    {
        return is_string($value)
            ? (string) preg_replace('/[^a-f0-9]/', '', strtolower($value))
            : '';
    }

    /**
     * Returns the common REST argument schema for owned sessions.
     *
     * @return array<string, mixed>
     */
    private function sessionIdArguments(): array
    {
        return [
            'sessionId' => [
                'type' => 'string',
                'required' => true,
                'pattern' => '^[a-f0-9]{48}$',
                'sanitize_callback' => [$this, 'sanitizeSessionId'],
                'validate_callback' => [$this, 'validateSessionId'],
            ],
        ];
    }

    /**
     * Gets a request parameter without a compile-time WordPress dependency.
     *
     * @param mixed  $request REST request.
     * @param string $name    Parameter name.
     * @return mixed
     */
    private function requestParameter($request, string $name)
    {
        if (!is_object($request) || !is_callable([$request, 'get_param'])) {
            return null;
        }

        return call_user_func([$request, 'get_param'], $name);
    }

    /**
     * Gets the current authenticated WordPress user ID.
     */
    private function currentUserId(): int
    {
        if (!function_exists('get_current_user_id')) {
            return 0;
        }

        $userId = get_current_user_id();

        return is_numeric($userId) ? (int) $userId : 0;
    }

    /**
     * Maps internal status keys to the settings UI contract.
     *
     * @param mixed $status Internal status or WP_Error.
     * @return array<string, mixed>|object
     */
    private function formatStatus($status)
    {
        if (!is_array($status)) {
            return is_object($status)
                ? $status
                : OAuthError::create('oauth_status_invalid', 'The authentication status is invalid.', 500);
        }

        return [
            'mode' => ($status['mode'] ?? '') === AuthenticationMode::MODE_OAUTH
                ? AuthenticationMode::MODE_OAUTH
                : AuthenticationMode::MODE_API_KEY,
            'apiKey' => [
                'configured' => ($status['has_api_key'] ?? false) === true,
                'source' => is_string($status['api_key_source'] ?? null)
                    ? $status['api_key_source']
                    : 'none',
            ],
            'oauth' => [
                'connected' => ($status['oauth_connected'] ?? false) === true,
                'accountLabel' => is_string($status['oauth_account_label'] ?? null)
                    ? $status['oauth_account_label']
                    : '',
                'errorCode' => is_string($status['oauth_error_code'] ?? null)
                    ? $status['oauth_error_code']
                    : '',
                'errorMessage' => is_string($status['oauth_error_message'] ?? null)
                    ? $status['oauth_error_message']
                    : '',
            ],
            'canUseOAuth' => ($status['encryption_available'] ?? false) === true,
        ];
    }

    /**
     * Maps an internal device session to the settings UI contract.
     *
     * @param mixed $started Internal session or WP_Error.
     * @return array<string, mixed>|object
     */
    private function formatStart($started)
    {
        if (!is_array($started)) {
            return is_object($started)
                ? $started
                : OAuthError::create('oauth_start_invalid', 'The OAuth start response is invalid.', 500);
        }

        $expiresAt = isset($started['expires_at']) && is_numeric($started['expires_at'])
            ? (int) $started['expires_at']
            : time() + 900;

        return [
            'sessionId' => is_string($started['session_id'] ?? null) ? $started['session_id'] : '',
            'userCode' => is_string($started['user_code'] ?? null) ? $started['user_code'] : '',
            'verificationUrl' => is_string($started['verification_url'] ?? null)
                ? $started['verification_url']
                : '',
            'expiresIn' => max(1, $expiresAt - time()),
            'pollInterval' => isset($started['interval']) && is_numeric($started['interval'])
                ? (int) $started['interval']
                : 5,
        ];
    }

    /**
     * Maps internal poll data to the settings UI contract.
     *
     * @param mixed $polled Internal poll result or WP_Error.
     * @return array<string, mixed>|object
     */
    private function formatPoll($polled)
    {
        if (!is_array($polled)) {
            return is_object($polled)
                ? $polled
                : OAuthError::create('oauth_poll_invalid', 'The OAuth poll response is invalid.', 500);
        }

        $response = [
            'status' => is_string($polled['status'] ?? null) ? $polled['status'] : 'error',
        ];
        if (isset($polled['retry_after']) && is_numeric($polled['retry_after'])) {
            $response['retryAfter'] = max(1, (int) $polled['retry_after']);
        }
        if (isset($polled['message']) && is_string($polled['message']) && $polled['message'] !== '') {
            $response['message'] = $polled['message'];
        }
        if (($polled['status'] ?? '') === 'approved') {
            $response['connected'] = true;
            $response['mode'] = AuthenticationMode::MODE_OAUTH;
        }

        return $response;
    }

    /**
     * Converts successful arrays to REST responses while preserving WP_Error.
     *
     * @param mixed $value Response value.
     * @return mixed
     */
    private function respond($value)
    {
        if (OAuthError::is($value) || !function_exists('rest_ensure_response')) {
            return $value;
        }

        return rest_ensure_response($value);
    }
}
