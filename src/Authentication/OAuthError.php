<?php

declare(strict_types=1);

namespace WordPress\OpenAiAiProvider\Authentication;

use RuntimeException;

/**
 * Creates and inspects WordPress errors without making WordPress a Composer dependency.
 *
 * @since 1.1.0
 */
final class OAuthError
{
    /**
     * Creates a WP_Error with a REST-friendly status code.
     *
     * @since 1.1.0
     *
     * @param string               $code    Stable machine-readable error code.
     * @param string               $message Human-readable error message.
     * @param int                  $status  HTTP status code.
     * @param array<string, mixed> $extra   Additional non-secret error data.
     * @return object WP_Error instance.
     */
    public static function create(string $code, string $message, int $status = 500, array $extra = []): object
    {
        if (!class_exists('WP_Error')) {
            throw new RuntimeException($message);
        }

        $data = array_merge(['status' => $status], $extra);

        return new \WP_Error($code, $message, $data);
    }

    /**
     * Checks whether a value is a WP_Error.
     *
     * @since 1.1.0
     *
     * @param mixed $value Value to inspect.
     */
    public static function is($value): bool
    {
        if (!function_exists('is_wp_error')) {
            return false;
        }

        return (bool) is_wp_error($value);
    }

    /**
     * Gets a WP_Error code without requiring a compile-time WordPress type.
     *
     * @since 1.1.0
     *
     * @param mixed $error Possible WP_Error.
     */
    public static function code($error): string
    {
        if (!is_object($error) || !is_callable([$error, 'get_error_code'])) {
            return '';
        }

        $code = call_user_func([$error, 'get_error_code']);

        return is_string($code) ? $code : '';
    }

    /**
     * Gets a WP_Error message without requiring a compile-time WordPress type.
     *
     * @since 1.1.0
     *
     * @param mixed $error Possible WP_Error.
     */
    public static function message($error): string
    {
        if (!is_object($error) || !is_callable([$error, 'get_error_message'])) {
            return '';
        }

        $message = call_user_func([$error, 'get_error_message']);

        return is_string($message) ? $message : '';
    }

    /**
     * Gets WP_Error data without requiring a compile-time WordPress type.
     *
     * @since 1.1.0
     *
     * @param mixed $error Possible WP_Error.
     * @return array<string, mixed>
     */
    public static function data($error): array
    {
        if (!is_object($error) || !is_callable([$error, 'get_error_data'])) {
            return [];
        }

        $data = call_user_func([$error, 'get_error_data']);
        if (!is_array($data)) {
            return [];
        }

        /** @var array<string, mixed> $data */
        return $data;
    }
}
