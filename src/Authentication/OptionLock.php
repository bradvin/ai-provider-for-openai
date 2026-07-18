<?php

declare(strict_types=1);

namespace WordPress\OpenAiAiProvider\Authentication;

use Throwable;

/**
 * Small, non-autoloaded option lock for refresh and device polling work.
 *
 * @since 1.1.0
 */
final class OptionLock
{
    /** @var string */
    private $optionName;

    /** @var int */
    private $ttl;

    /**
     * @since 1.1.0
     */
    public function __construct(string $optionName, int $ttl = 15)
    {
        $this->optionName = $optionName;
        $this->ttl = max(3, min(60, $ttl));
    }

    /**
     * Acquires the lock.
     *
     * @since 1.1.0
     *
     * @return string|object Owner ID on success, WP_Error otherwise.
     */
    public function acquire()
    {
        if (
            !function_exists('add_option')
            || !function_exists('get_option')
            || !function_exists('delete_option')
        ) {
            return OAuthError::create(
                'oauth_lock_unavailable',
                'WordPress option storage is unavailable.',
                500
            );
        }

        $owner = $this->createOwner();
        $value = [
            'owner' => $owner,
            'expires_at' => time() + $this->ttl,
        ];

        if (add_option($this->optionName, $value, '', false)) {
            return $owner;
        }

        $current = get_option($this->optionName, null);
        if (
            is_array($current)
            && isset($current['expires_at'])
            && is_numeric($current['expires_at'])
            && (int) $current['expires_at'] <= time()
        ) {
            delete_option($this->optionName);
            if (add_option($this->optionName, $value, '', false)) {
                return $owner;
            }
        }

        return OAuthError::create(
            'oauth_operation_locked',
            'Another authentication operation is already in progress.',
            409,
            ['retry_after' => 1]
        );
    }

    /**
     * Releases a lock only when the caller still owns it.
     *
     * @since 1.1.0
     */
    public function release(string $owner): void
    {
        if (!function_exists('get_option') || !function_exists('delete_option')) {
            return;
        }

        $current = get_option($this->optionName, null);
        if (
            is_array($current)
            && isset($current['owner'])
            && is_string($current['owner'])
            && hash_equals($current['owner'], $owner)
        ) {
            delete_option($this->optionName);
        }
    }

    /**
     * Creates a cryptographically random lock owner identifier.
     */
    private function createOwner(): string
    {
        try {
            return bin2hex(random_bytes(16));
        } catch (Throwable $throwable) {
            return hash('sha256', uniqid($this->optionName, true));
        }
    }
}
