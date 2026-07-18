<?php

declare(strict_types=1);

namespace WordPress\OpenAiAiProvider\Models;

use WordPress\AiClient\Common\Exception\RuntimeException;
use WordPress\AiClient\Providers\Http\DTO\Response;

/**
 * Reconstructs a Responses API response from the Codex backend's SSE stream.
 *
 * The Codex endpoint may omit the output array from its terminal event. Output
 * items are therefore collected from response.output_item.done events instead.
 *
 * @since 1.1.0
 */
final class OpenAiCodexStreamResponseParser
{
    /**
     * Converts an SSE response into the JSON response shape used by the model.
     *
     * @since 1.1.0
     *
     * @param Response $response The raw SSE response.
     * @return Response A response whose body contains normalized JSON.
     */
    public static function parse(Response $response): Response
    {
        $body = $response->getBody();
        if ($body === null || trim($body) === '') {
            throw new RuntimeException('The OpenAI account response stream was empty.');
        }

        $outputItems = [];
        $textDeltas = [];
        $activeMessagePhase = null;
        $sawToolCall = false;
        $sawTerminalEvent = false;
        $terminalEventType = '';
        $terminalResponse = [];

        foreach (self::decodeEvents($body) as $event) {
            $eventType = isset($event['type']) && is_string($event['type'])
                ? $event['type']
                : '';

            if ($eventType === 'error') {
                throw new RuntimeException(self::getErrorMessage($event));
            }

            if ($eventType === 'response.output_item.added') {
                $item = isset($event['item']) && is_array($event['item'])
                    ? $event['item']
                    : [];
                if (($item['type'] ?? '') === 'message') {
                    $activeMessagePhase = self::normalizePhase($item['phase'] ?? null);
                } else {
                    $activeMessagePhase = null;
                }
                if (($item['type'] ?? '') === 'function_call') {
                    $sawToolCall = true;
                }
                continue;
            }

            if (strpos($eventType, 'function_call') !== false) {
                $sawToolCall = true;
            }

            if ($eventType === 'response.output_text.delta') {
                if (
                    $activeMessagePhase !== 'analysis'
                    && $activeMessagePhase !== 'commentary'
                    && isset($event['delta'])
                    && is_string($event['delta'])
                ) {
                    $textDeltas[] = $event['delta'];
                }
                continue;
            }

            if ($eventType === 'response.output_item.done') {
                if (!isset($event['item']) || !is_array($event['item'])) {
                    continue;
                }

                $item = $event['item'];
                $phase = self::normalizePhase($item['phase'] ?? null);
                $itemType = isset($item['type']) && is_string($item['type'])
                    ? $item['type']
                    : '';
                if ($itemType === 'function_call') {
                    $sawToolCall = true;
                }
                if (
                    ($itemType === 'message' || $itemType === 'function_call')
                    && $phase !== 'analysis'
                    && $phase !== 'commentary'
                ) {
                    $outputItems[] = $item;
                }
                continue;
            }

            if (
                $eventType === 'response.completed'
                || $eventType === 'response.incomplete'
                || $eventType === 'response.failed'
            ) {
                $sawTerminalEvent = true;
                $terminalEventType = $eventType;
                if (isset($event['response']) && is_array($event['response'])) {
                    /** @var array<string, mixed> $terminalResponse */
                    $terminalResponse = $event['response'];
                } else {
                    $terminalResponse = [];
                }

                if ($eventType === 'response.failed') {
                    throw new RuntimeException(self::getErrorMessage($terminalResponse));
                }
                break;
            }
        }

        if (!$outputItems && $textDeltas && !$sawToolCall) {
            $outputItems[] = [
                'type' => 'message',
                'role' => 'assistant',
                'status' => 'completed',
                'content' => [
                    [
                        'type' => 'output_text',
                        'text' => implode('', $textDeltas),
                    ],
                ],
            ];
        }

        if (!$sawTerminalEvent) {
            throw new RuntimeException(
                'The OpenAI account response stream ended before it reported completion.'
            );
        }

        /*
         * Some Codex responses currently return a null terminal output. Never
         * use it to replace the output reconstructed from the stream events.
         */
        $normalized = $terminalResponse;
        $normalized['output'] = $outputItems;
        if (!isset($normalized['status']) || !is_string($normalized['status'])) {
            $normalized['status'] = $terminalEventType === 'response.incomplete'
                ? 'incomplete'
                : 'completed';
        }
        if ($textDeltas) {
            $normalized['output_text'] = implode('', $textDeltas);
        }

        $normalizedBody = json_encode($normalized);
        if (!is_string($normalizedBody)) {
            throw new RuntimeException('The OpenAI account response could not be decoded.');
        }

        return new Response(
            $response->getStatusCode(),
            $response->getHeaders(),
            $normalizedBody
        );
    }

    /**
     * Decodes JSON data fields from an SSE response body.
     *
     * @since 1.1.0
     *
     * @param string $body The SSE response body.
     * @return list<array<string, mixed>> Decoded events.
     */
    private static function decodeEvents(string $body): array
    {
        $events = [];
        $normalizedBody = str_replace(["\r\n", "\r"], "\n", $body);
        $frames = preg_split('/\n{2,}/', trim($normalizedBody));
        if (!is_array($frames)) {
            return $events;
        }

        foreach ($frames as $frame) {
            $dataLines = [];
            foreach (explode("\n", $frame) as $line) {
                if (strncmp($line, 'data:', 5) !== 0) {
                    continue;
                }
                $dataLines[] = ltrim(substr($line, 5), ' ');
            }

            if (!$dataLines) {
                continue;
            }

            $data = implode("\n", $dataLines);
            if ($data === '[DONE]') {
                continue;
            }

            $decoded = json_decode($data, true);
            if (is_array($decoded) && !array_is_list($decoded)) {
                /** @var array<string, mixed> $decoded */
                $events[] = $decoded;
            }
        }

        return $events;
    }

    /**
     * Gets the most useful message from an error event or response.
     *
     * @since 1.1.0
     *
     * @param array<string, mixed> $data The event or response data.
     * @return string The error message.
     */
    private static function getErrorMessage(array $data): string
    {
        $error = isset($data['error']) && is_array($data['error'])
            ? $data['error']
            : $data;

        $message = isset($error['message']) && is_string($error['message'])
            ? trim($error['message'])
            : '';
        $code = isset($error['code']) && is_scalar($error['code'])
            ? trim((string) $error['code'])
            : '';

        if ($message === '') {
            $message = 'OpenAI account authentication returned an error.';
        }
        if ($code !== '') {
            return sprintf('%s (%s)', $message, $code);
        }
        return $message;
    }

    /**
     * Normalizes a Codex message phase.
     *
     * @since 1.1.0
     *
     * @param mixed $phase The phase value.
     * @return string|null The normalized phase.
     */
    private static function normalizePhase($phase): ?string
    {
        if (!is_string($phase) || trim($phase) === '') {
            return null;
        }
        return strtolower(trim($phase));
    }
}
