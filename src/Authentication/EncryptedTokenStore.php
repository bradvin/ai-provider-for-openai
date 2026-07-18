<?php

declare(strict_types=1);

namespace WordPress\OpenAiAiProvider\Authentication;

use Throwable;

/**
 * Stores one site-wide Codex OAuth token pair encrypted at rest.
 *
 * AES-256-GCM supplies authenticated encryption. The encryption key is derived
 * from WordPress salts and is never persisted alongside the ciphertext.
 *
 * @since 1.1.0
 */
final class EncryptedTokenStore
{
    public const OPTION_NAME = '_ai_provider_for_openai_oauth_tokens';

    private const CIPHER = 'aes-256-gcm';
    private const FORMAT_VERSION = 1;
    private const TAG_LENGTH = 16;
    private const KEY_CONTEXT = 'ai-provider-for-openai/oauth-token-store/v1';

    /**
     * Checks whether authenticated encryption can be used.
     *
     * @since 1.1.0
     */
    public function isEncryptionAvailable(): bool
    {
        if (
            !function_exists('openssl_encrypt')
            || !function_exists('openssl_decrypt')
            || !function_exists('openssl_cipher_iv_length')
            || !function_exists('openssl_get_cipher_methods')
            || !function_exists('wp_salt')
        ) {
            return false;
        }

        $methods = array_map('strtolower', openssl_get_cipher_methods());

        return in_array(self::CIPHER, $methods, true);
    }

    /**
     * Gets and decrypts the stored token set.
     *
     * @since 1.1.0
     *
     * @return array<string, mixed>|object|null Token set, WP_Error, or null when absent.
     */
    public function getTokens()
    {
        if (!function_exists('get_option')) {
            return OAuthError::create(
                'oauth_token_storage_unavailable',
                'WordPress option storage is unavailable.',
                500
            );
        }

        $stored = get_option(self::OPTION_NAME, null);
        if ($stored === null || $stored === false || $stored === '') {
            return null;
        }

        if (!$this->isEncryptionAvailable()) {
            return OAuthError::create(
                'oauth_encryption_unavailable',
                'OpenSSL AES-256-GCM support and WordPress salts are required for OAuth.',
                500
            );
        }

        if (!is_string($stored)) {
            return OAuthError::create(
                'oauth_token_storage_invalid',
                'The stored OAuth credentials are invalid.',
                500
            );
        }

        $decodedEnvelope = json_decode($stored, true);
        if (!is_array($decodedEnvelope)) {
            return OAuthError::create(
                'oauth_token_storage_invalid',
                'The stored OAuth credentials could not be decoded.',
                500
            );
        }

        /** @var array<string, mixed> $envelope */
        $envelope = $decodedEnvelope;
        if (!$this->isValidEnvelope($envelope)) {
            return OAuthError::create(
                'oauth_token_storage_invalid',
                'The stored OAuth credentials could not be decoded.',
                500
            );
        }

        $ivValue = $envelope['iv'] ?? null;
        $tagValue = $envelope['tag'] ?? null;
        $ciphertextValue = $envelope['ciphertext'] ?? null;
        if (!is_string($ivValue) || !is_string($tagValue) || !is_string($ciphertextValue)) {
            return OAuthError::create(
                'oauth_token_storage_invalid',
                'The stored OAuth credentials could not be decoded.',
                500
            );
        }

        $iv = base64_decode($ivValue, true);
        $tag = base64_decode($tagValue, true);
        $ciphertext = base64_decode($ciphertextValue, true);
        if ($iv === false || $tag === false || $ciphertext === false || strlen($tag) !== self::TAG_LENGTH) {
            return OAuthError::create(
                'oauth_token_storage_invalid',
                'The stored OAuth credentials could not be decoded.',
                500
            );
        }

        $key = $this->encryptionKey();
        if (!is_string($key)) {
            return $key;
        }

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            self::KEY_CONTEXT
        );
        if (!is_string($plaintext)) {
            return OAuthError::create(
                'oauth_token_decryption_failed',
                'The OAuth credentials could not be decrypted with the current WordPress salts.',
                500
            );
        }

        $decodedTokens = json_decode($plaintext, true);
        if (!is_array($decodedTokens)) {
            return OAuthError::create(
                'oauth_token_storage_invalid',
                'The decrypted OAuth credentials are invalid.',
                500
            );
        }

        /** @var array<string, mixed> $tokens */
        $tokens = $decodedTokens;
        if (!$this->isValidTokenSet($tokens)) {
            return OAuthError::create(
                'oauth_token_storage_invalid',
                'The decrypted OAuth credentials are invalid.',
                500
            );
        }

        return $tokens;
    }

    /**
     * Encrypts and stores a token set in a non-autoloaded option.
     *
     * @since 1.1.0
     *
     * @param array<string, mixed> $tokens OAuth token data.
     * @return true|object True on success or WP_Error.
     */
    public function saveTokens(array $tokens)
    {
        if (!$this->isEncryptionAvailable()) {
            return OAuthError::create(
                'oauth_encryption_unavailable',
                'OpenSSL AES-256-GCM support and WordPress salts are required for OAuth.',
                500
            );
        }

        if (!$this->isValidTokenSet($tokens)) {
            return OAuthError::create(
                'oauth_token_set_invalid',
                'The OAuth token response did not contain usable credentials.',
                502
            );
        }

        if (
            !function_exists('add_option')
            || !function_exists('update_option')
            || !function_exists('get_option')
        ) {
            return OAuthError::create(
                'oauth_token_storage_unavailable',
                'WordPress option storage is unavailable.',
                500
            );
        }

        $key = $this->encryptionKey();
        if (!is_string($key)) {
            return $key;
        }

        $ivLength = openssl_cipher_iv_length(self::CIPHER);
        if (!is_int($ivLength) || $ivLength < 1) {
            return OAuthError::create(
                'oauth_encryption_unavailable',
                'AES-256-GCM initialization failed.',
                500
            );
        }

        try {
            $iv = random_bytes($ivLength);
        } catch (Throwable $throwable) {
            return OAuthError::create(
                'oauth_random_source_failed',
                'A secure random source is required to store OAuth credentials.',
                500
            );
        }

        $plaintext = json_encode($tokens, JSON_UNESCAPED_SLASHES);
        if (!is_string($plaintext)) {
            return OAuthError::create(
                'oauth_token_encoding_failed',
                'The OAuth credentials could not be encoded.',
                500
            );
        }

        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            self::KEY_CONTEXT,
            self::TAG_LENGTH
        );
        if (!is_string($ciphertext) || strlen($tag) !== self::TAG_LENGTH) {
            return OAuthError::create(
                'oauth_encryption_failed',
                'The OAuth credentials could not be encrypted.',
                500
            );
        }

        $envelope = [
            'version' => self::FORMAT_VERSION,
            'cipher' => self::CIPHER,
            'iv' => base64_encode($iv),
            'tag' => base64_encode($tag),
            'ciphertext' => base64_encode($ciphertext),
        ];
        $encoded = json_encode($envelope, JSON_UNESCAPED_SLASHES);
        if (!is_string($encoded)) {
            return OAuthError::create(
                'oauth_token_encoding_failed',
                'The encrypted OAuth credentials could not be encoded.',
                500
            );
        }

        if (!add_option(self::OPTION_NAME, $encoded, '', false)) {
            update_option(self::OPTION_NAME, $encoded, false);
        }

        if (get_option(self::OPTION_NAME, null) !== $encoded) {
            return OAuthError::create(
                'oauth_token_storage_failed',
                'The OAuth credentials could not be saved.',
                500
            );
        }

        return true;
    }

    /**
     * Deletes all stored OAuth credentials.
     *
     * @since 1.1.0
     *
     * @return true|object True on success or WP_Error.
     */
    public function deleteTokens()
    {
        if (!function_exists('delete_option') || !function_exists('get_option')) {
            return OAuthError::create(
                'oauth_token_storage_unavailable',
                'WordPress option storage is unavailable.',
                500
            );
        }

        delete_option(self::OPTION_NAME);

        $remaining = get_option(self::OPTION_NAME, null);
        if ($remaining !== null && $remaining !== false && $remaining !== '') {
            return OAuthError::create(
                'oauth_token_deletion_failed',
                'The OAuth credentials could not be removed.',
                500
            );
        }

        return true;
    }

    /**
     * Derives a 256-bit encryption key from independent WordPress salts.
     *
     * @return string|object Raw key bytes or WP_Error.
     */
    private function encryptionKey()
    {
        if (!function_exists('wp_salt')) {
            return OAuthError::create(
                'oauth_encryption_unavailable',
                'WordPress salts are unavailable.',
                500
            );
        }

        $authSalt = wp_salt('auth');
        $secureAuthSalt = wp_salt('secure_auth');
        if (!is_string($authSalt) || !is_string($secureAuthSalt)) {
            return OAuthError::create(
                'oauth_encryption_unavailable',
                'WordPress salts are not configured.',
                500
            );
        }

        $material = $authSalt . "\0" . $secureAuthSalt;
        if ($material === "\0") {
            return OAuthError::create(
                'oauth_encryption_unavailable',
                'WordPress salts are not configured.',
                500
            );
        }

        return hash_hmac('sha256', self::KEY_CONTEXT, $material, true);
    }

    /**
     * Validates an encrypted storage envelope.
     *
     * @param array<string, mixed> $envelope Envelope data.
     */
    private function isValidEnvelope(array $envelope): bool
    {
        return ($envelope['version'] ?? null) === self::FORMAT_VERSION
            && ($envelope['cipher'] ?? null) === self::CIPHER
            && isset($envelope['iv'], $envelope['tag'], $envelope['ciphertext'])
            && is_string($envelope['iv'])
            && is_string($envelope['tag'])
            && is_string($envelope['ciphertext']);
    }

    /**
     * Validates the minimum usable token-set shape.
     *
     * @param array<string, mixed> $tokens Token data.
     */
    private function isValidTokenSet(array $tokens): bool
    {
        return isset($tokens['access_token'], $tokens['refresh_token'], $tokens['expires_at'])
            && is_string($tokens['access_token'])
            && trim($tokens['access_token']) !== ''
            && is_string($tokens['refresh_token'])
            && trim($tokens['refresh_token']) !== ''
            && is_numeric($tokens['expires_at'])
            && (int) $tokens['expires_at'] > 0;
    }
}
