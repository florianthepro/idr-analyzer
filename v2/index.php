<?php

declare(strict_types=1);

$config = json_decode(
    file_get_contents(__DIR__ . '/data.json'),
    true
);

function flatten($data, string $path = ''): array
{
    $result = [];

    if (is_array($data)) {

        foreach ($data as $key => $value) {

            $newPath = $path === ''
                ? (string)$key
                : $path . '.' . $key;

            if (is_array($value)) {
                $result += flatten($value, $newPath);
            } else {
                $result[$newPath] = (string)$value;
            }
        }
    }

    return $result;
}

function extractEntities(
    array $flat,
    array $config
): array {

    $entities = [];

    foreach (
        ($config['entity_patterns'] ?? [])
        as $entityType => $patterns
    ) {

        foreach ($patterns as $pattern) {

            foreach ($flat as $value) {

                preg_match_all(
                    '/' . $pattern . '/i',
                    $value,
                    $matches
                );

                foreach ($matches[0] ?? [] as $match) {

                    $entities[$entityType][] = $match;
                }
            }
        }
    }

    foreach ($entities as $type => $values) {
        $entities[$type] =
            array_values(array_unique($values));
    }

    return $entities;
}

function normalizeFields(
    array $flat,
    array $config
): array {

    $normalized = [];

    foreach (
        ($config['field_aliases'] ?? [])
        as $canonical => $aliases
    ) {

        foreach ($flat as $key => $value) {

            foreach ($aliases as $alias) {

                if (
                    stripos($key, $alias) !== false
                ) {

                    $normalized[$canonical][$key] =
                        $value;
                }
            }
        }
    }

    return $normalized;
}

function detectEvents(
    array $flat,
    array $config
): array {

    $events = [];

    foreach (
        ($config['event_catalog'] ?? [])
        as $eventName => $eventConfig
    ) {

        foreach ($flat as $key => $value) {

            foreach (
                ($eventConfig['match'] ?? [])
                as $indicator
            ) {

                if (
                    stripos(
                        $key . ' ' . $value,
                        $indicator
                    ) !== false
                ) {

                    $events[$eventName] =
                        $eventConfig;

                    break 2;
                }
            }
        }
    }

    return $events;
}

function executeRules(
    array $flat,
    array $config
): array {

    $score = 0;

    $findings = [];

    foreach (
        ($config['rules'] ?? [])
        as $rule
    ) {

        $matched = false;

        foreach ($flat as $key => $value) {
