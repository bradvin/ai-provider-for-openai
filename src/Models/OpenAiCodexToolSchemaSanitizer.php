<?php

declare(strict_types=1);

namespace WordPress\OpenAiAiProvider\Models;

/**
 * Normalizes function schemas for the stricter account-backed Codex endpoint.
 *
 * The public OpenAI API accepts schema hints that the Codex backend can reject
 * while compiling tools. Removing those hints keeps the structural schema and
 * lets the WordPress-side tool handler remain the final argument validator.
 *
 * @since 1.1.0
 */
final class OpenAiCodexToolSchemaSanitizer
{
    private const MAX_DEPTH = 32;

    /**
     * Sanitizes Responses API function tools without mutating caller data.
     *
     * @since 1.1.0
     *
     * @param list<array<string, mixed>> $tools Function tool definitions.
     * @return list<array<string, mixed>> Sanitized tool definitions.
     */
    public static function sanitize(array $tools): array
    {
        foreach ($tools as $index => $tool) {
            if (!isset($tool['parameters']) || !is_array($tool['parameters'])) {
                continue;
            }

            $parameters = self::sanitizeNode($tool['parameters'], 0);
            $parameters['type'] = 'object';
            foreach (['allOf', 'anyOf', 'oneOf', 'enum', 'not'] as $keyword) {
                unset($parameters[$keyword]);
            }

            $tools[$index]['parameters'] = $parameters;
        }

        return $tools;
    }

    /**
     * Recursively removes schema hints known to break strict tool compilers.
     *
     * @param array<mixed> $node  JSON Schema node or list.
     * @param int          $depth Current recursion depth.
     * @return array<mixed> Sanitized node.
     */
    private static function sanitizeNode(array $node, int $depth): array
    {
        if ($depth >= self::MAX_DEPTH) {
            return $node;
        }

        $isSchemaNode = isset($node['type'])
            || isset($node['allOf'])
            || isset($node['anyOf'])
            || isset($node['oneOf']);
        if ($isSchemaNode) {
            unset($node['pattern'], $node['format']);
        }

        if (isset($node['enum']) && is_array($node['enum'])) {
            foreach ($node['enum'] as $enumValue) {
                if (is_string($enumValue) && strpos($enumValue, '/') !== false) {
                    unset($node['enum']);
                    break;
                }
            }
        }

        if (isset($node['$ref'])) {
            unset($node['default']);
        }

        foreach ($node as $key => $value) {
            if (is_array($value)) {
                $node[$key] = self::sanitizeNode($value, $depth + 1);
            }
        }

        return $node;
    }
}
