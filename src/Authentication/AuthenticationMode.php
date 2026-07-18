<?php

declare(strict_types=1);

namespace WordPress\OpenAiAiProvider\Authentication;

/**
 * Persists and validates the site's selected OpenAI authentication mode.
 *
 * @since 1.1.0
 */
final class AuthenticationMode
{
    public const MODE_API_KEY = 'api_key';
    public const MODE_OAUTH = 'oauth';
    public const OPTION_NAME = 'ai_provider_for_openai_auth_mode';
    public const API_KEY_OPTION_NAME = 'connectors_ai_openai_api_key';

    /** @var EncryptedTokenStore */
    private $tokenStore;

    /**
     * @since 1.1.0
     */
    public function __construct(?EncryptedTokenStore $tokenStore = null)
    {
        $this->tokenStore = $tokenStore ?? new EncryptedTokenStore();
    }

    /**
     * Gets the selected mode, defaulting safely to API-key authentication.
     *
     * @since 1.1.0
     */
    public function get(): string
    {
        if (!function_exists('get_option')) {
            return self::MODE_API_KEY;
        }

        $mode = get_option(self::OPTION_NAME, self::MODE_API_KEY);

        return $mode === self::MODE_OAUTH ? self::MODE_OAUTH : self::MODE_API_KEY;
    }

    /**
     * Selects an authentication mode.
     *
     * OAuth can only be selected when a complete encrypted token pair exists.
     * API-key mode remains selectable without a key so the settings screen can
     * reveal its entry form after a disconnect.
     *
     * @since 1.1.0
     *
     * @return true|object True or WP_Error.
     */
    public function set(string $mode)
    {
        if (!in_array($mode, [self::MODE_API_KEY, self::MODE_OAUTH], true)) {
            return OAuthError::create(
                'authentication_mode_invalid',
                'Choose either API-key or OAuth authentication.',
                400
            );
        }

        if ($mode === self::MODE_OAUTH) {
            $tokens = $this->tokenStore->getTokens();
            if (is_object($tokens)) {
                return $tokens;
            }
            if (!is_array($tokens)) {
                return OAuthError::create(
                    'oauth_credentials_missing',
                    'Connect an OpenAI account before selecting OAuth.',
                    409
                );
            }
        }

        return $this->persist($mode);
    }

    /**
     * Resets to the safe default after OAuth credentials are deleted.
     *
     * @since 1.1.0
     *
     * @return true|object True or WP_Error.
     */
    public function resetToApiKey()
    {
        return $this->persist(self::MODE_API_KEY);
    }

    /**
     * Checks the Core Connectors API-key option and environment fallback.
     *
     * @since 1.1.0
     */
    public function hasApiKey(): bool
    {
        return $this->apiKeySource() !== 'none';
    }

    /**
     * Returns the source of the configured API key without returning its value.
     *
     * @since 1.1.0
     */
    public function apiKeySource(): string
    {
        $environment = getenv('OPENAI_API_KEY');
        if (is_string($environment) && trim($environment) !== '') {
            return 'env';
        }

        if (defined('OPENAI_API_KEY')) {
            $constant = constant('OPENAI_API_KEY');
            if (is_string($constant) && trim($constant) !== '') {
                return 'constant';
            }
        }

        if (function_exists('get_option')) {
            $option = get_option(self::API_KEY_OPTION_NAME, '');
            if (is_string($option) && trim($option) !== '') {
                return 'database';
            }
        }

        return 'none';
    }

    /**
     * Checks whether a complete encrypted OAuth token pair exists.
     *
     * @since 1.1.0
     *
     * @return bool|object Boolean or WP_Error when stored data is unreadable.
     */
    public function hasOAuthCredentials()
    {
        $tokens = $this->tokenStore->getTokens();
        if (is_object($tokens)) {
            return $tokens;
        }

        return is_array($tokens);
    }

    /**
     * Persists a non-sensitive, non-autoloaded mode option.
     *
     * @return true|object True or WP_Error.
     */
    private function persist(string $mode)
    {
        if (
            !function_exists('add_option')
            || !function_exists('update_option')
            || !function_exists('get_option')
        ) {
            return OAuthError::create(
                'authentication_mode_storage_unavailable',
                'WordPress option storage is unavailable.',
                500
            );
        }

        $previous = $this->get();
        if (!add_option(self::OPTION_NAME, $mode, '', false)) {
            update_option(self::OPTION_NAME, $mode, false);
        }
        if (get_option(self::OPTION_NAME, self::MODE_API_KEY) !== $mode) {
            return OAuthError::create(
                'authentication_mode_storage_failed',
                'The authentication mode could not be saved.',
                500
            );
        }

        if ($previous !== $mode && function_exists('do_action')) {
            do_action('ai_provider_for_openai_auth_changed');
        }

        return true;
    }
}
