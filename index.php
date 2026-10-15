<?php

declare(strict_types=1);

const MAX_INPUT_BYTES = 26214400;

function escapeHtml(mixed $value): string
{
    return htmlspecialchars(
        (string)$value,
        ENT_QUOTES | ENT_SUBSTITUTE,
        'UTF-8'
    );
}

function valueToText(mixed $value): string
{
    if (is_bool($value)) {
        return $value ? 'Ja' : 'Nein';
    }

    if ($value === null) {
        return '';
    }

    if (is_scalar($value)) {
        return trim((string)$value);
    }

    return json_encode(
        $value,
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    ) ?: '';
}

function decodeInvestigation(string $input): mixed
{
    $input = trim($input);

    if ($input === '') {
        throw new RuntimeException(
            'Keine Investigation eingefügt.'
        );
    }

    if (strlen($input) > MAX_INPUT_BYTES) {
        throw new RuntimeException(
            'Die Investigation ist zu groß.'
        );
    }

    $htmlDecoded = html_entity_decode(
        $input,
        ENT_QUOTES | ENT_HTML5,
        'UTF-8'
    );

    $candidates = array_unique([
        $input,
        $htmlDecoded,
        trim(strip_tags($htmlDecoded))
    ]);

    foreach ($candidates as $candidate) {
        $decoded = json_decode(
            $candidate,
            true,
            128,
            JSON_BIGINT_AS_STRING
        );

        if (json_last_error() === JSON_ERROR_NONE) {
            return $decoded;
        }
    }

    $records = [];

    foreach (preg_split('/\R/u', $input) ?: [] as $line) {
        $line = trim($line);

        if ($line === '') {
            continue;
        }

        $decoded = json_decode(
            $line,
            true,
            128,
            JSON_BIGINT_AS_STRING
        );

        if (json_last_error() !== JSON_ERROR_NONE) {
            $records = [];
            break;
        }

        $records[] = $decoded;
    }

    if ($records !== []) {
        return $records;
    }

    throw new RuntimeException(
        'Ungültiges JSON oder NDJSON.'
    );
}

function expandEmbeddedJson(
    mixed $value,
    int $depth = 0
): mixed {
    if ($depth > 8) {
        return $value;
    }

    if (is_array($value)) {
        foreach ($value as $key => $child) {
            $value[$key] = expandEmbeddedJson(
                $child,
                $depth + 1
            );
        }

        return $value;
    }

    if (!is_string($value)) {
        return $value;
    }

    $candidate = trim(
        html_entity_decode(
            strip_tags($value),
            ENT_QUOTES | ENT_HTML5,
            'UTF-8'
        )
    );

    if (!in_array(
        $candidate[0] ?? '',
        ['{', '['],
        true
    )) {
        return $value;
    }

    $decoded = json_decode(
        $candidate,
        true,
        128,
        JSON_BIGINT_AS_STRING
    );

    if (json_last_error() !== JSON_ERROR_NONE) {
        return $value;
    }

    return expandEmbeddedJson(
        $decoded,
        $depth + 1
    );
}

function flattenJson(
    mixed $value,
    string $path = '',
    array &$result = []
): array {
    if (is_array($value)) {
        foreach ($value as $key => $child) {
            $nextPath = $path === ''
                ? (string)$key
                : $path . '.' . $key;

            flattenJson(
                $child,
                $nextPath,
                $result
            );
        }

        return $result;
    }

    $result[$path === '' ? '$' : $path] = $value;

    return $result;
}

function encodeInvestigationState(
    string $input
): string {
    $compressed = gzdeflate($input, 9);

    if ($compressed === false) {
        throw new RuntimeException(
            'Die Investigation konnte nicht komprimiert werden.'
        );
    }

    return rtrim(
        strtr(
            base64_encode($compressed),
            '+/',
            '-_'
        ),
        '='
    );
}

function decodeInvestigationState(
    string $state
): string {
    $padding = strlen($state) % 4;

    if ($padding !== 0) {
        $state .= str_repeat(
            '=',
            4 - $padding
        );
    }

    $decoded = base64_decode(
        strtr($state, '-_', '+/'),
        true
    );

    if ($decoded === false) {
        throw new RuntimeException(
            'Die Investigation im Link ist ungültig.'
        );
    }

    $inflated = @gzinflate($decoded);

    if ($inflated === false) {
        throw new RuntimeException(
            'Die Investigation im Link konnte nicht gelesen werden.'
        );
    }

    return $inflated;
}

function getNestedValue(
    array $data,
    string $path
): mixed {
    $current = $data;

    foreach (explode('.', $path) as $segment) {
        if (
            !is_array($current) ||
            !array_key_exists($segment, $current)
        ) {
            return null;
        }

        $current = $current[$segment];
    }

    return $current;
}

function extractRecords(
    mixed $decoded,
    array $config
): array {
    if (!is_array($decoded)) {
        return [
            ['value' => $decoded]
        ];
    }

    if (array_is_list($decoded)) {
        if ($decoded === []) {
            return [[]];
        }

        return array_map(
            static fn(mixed $value): array =>
                is_array($value)
                    ? $value
                    : ['value' => $value],
            $decoded
        );
    }

    foreach (
        $config['record_containers'] ?? []
        as $path
    ) {
        $records = getNestedValue(
            $decoded,
            (string)$path
        );

        if (
            is_array($records) &&
            array_is_list($records) &&
            $records !== []
        ) {
            return array_map(
                static fn(mixed $value): array =>
                    is_array($value)
                        ? $value
                        : ['value' => $value],
                $records
            );
        }
    }

    return [$decoded];
}

function normalizeFields(
    array $flat,
    array $config
): array {
    $normalized = [];

    foreach (
        $config['field_aliases'] ?? []
        as $canonical => $definition
    ) {
        $aliases = $definition['aliases']
            ?? $definition;

        foreach ($flat as $path => $value) {
            $leaf = strtolower(
                (string)preg_replace(
                    '/.*\./',
                    '',
                    $path
                )
            );

            $compactPath = strtolower(
                (string)preg_replace(
                    '/[^a-z0-9]+/i',
                    '',
                    $path
                )
            );

            foreach ((array)$aliases as $alias) {
                $alias = strtolower(
                    (string)$alias
                );

                $compactAlias = strtolower(
                    (string)preg_replace(
                        '/[^a-z0-9]+/i',
                        '',
                        $alias
                    )
                );

                $matches =
                    $leaf === $alias ||
                    (
                        $compactAlias !== '' &&
                        str_ends_with(
                            $compactPath,
                            $compactAlias
                        )
                    );

                if (!$matches) {
                    continue;
                }

                $text = valueToText($value);

                if (
                    $text !== '' &&
                    !in_array(
                        $text,
                        $normalized[
                            (string)$canonical
                        ] ?? [],
                        true
                    )
                ) {
                    $normalized[
                        (string)$canonical
                    ][] = $text;
                }

                break;
            }
        }
    }

    return $normalized;
}

function createSearchText(
    array $flat
): string {
    $parts = [];

    foreach ($flat as $path => $value) {
        $parts[] =
            $path . '=' . valueToText($value);
    }

    return strtolower(
        implode("\n", $parts)
    );
}

function matchesCondition(
    array $condition,
    string $searchText,
    array $normalized,
    array $events
): bool {
    if ($condition === []) {
        return false;
    }

    if (isset($condition['all'])) {
        foreach ($condition['all'] as $part) {
            if (
                !matchesCondition(
                    (array)$part,
                    $searchText,
                    $normalized,
                    $events
                )
            ) {
                return false;
            }
        }

        return true;
    }

    if (isset($condition['any'])) {
        foreach ($condition['any'] as $part) {
            if (
                matchesCondition(
                    (array)$part,
                    $searchText,
                    $normalized,
                    $events
                )
            ) {
                return true;
            }
        }

        return false;
    }

    if (isset($condition['not'])) {
        return !matchesCondition(
            (array)$condition['not'],
            $searchText,
            $normalized,
            $events
        );
    }

    if (isset($condition['event'])) {
        return in_array(
            (string)$condition['event'],
            array_column($events, 'id'),
            true
        );
    }

    if (isset($condition['any_text'])) {
        foreach (
            (array)$condition['any_text']
            as $needle
        ) {
            if (
                $needle !== '' &&
                str_contains(
                    $searchText,
                    strtolower((string)$needle)
                )
            ) {
                return true;
            }
        }

        return false;
    }

    if (isset($condition['all_text'])) {
        foreach (
            (array)$condition['all_text']
            as $needle
        ) {
            if (
                !str_contains(
                    $searchText,
                    strtolower((string)$needle)
                )
            ) {
                return false;
            }
        }

        return true;
    }

    if (!isset($condition['field'])) {
        return false;
    }

    $values = $normalized[
        (string)$condition['field']
    ] ?? [];

    if (array_key_exists(
        'exists',
        $condition
    )) {
        return
            (bool)$condition['exists'] ===
            ($values !== []);
    }

    foreach ($values as $value) {
        $lowerValue = strtolower($value);

        if (
            array_key_exists(
                'equals',
                $condition
            ) &&
            $lowerValue === strtolower(
                valueToText(
                    $condition['equals']
                )
            )
        ) {
            return true;
        }

        if (
            isset($condition['contains']) &&
            str_contains(
                $lowerValue,
                strtolower(
                    (string)$condition['contains']
                )
            )
        ) {
            return true;
        }

        if (
            isset($condition['in']) &&
            in_array(
                $lowerValue,
                array_map(
                    static fn(mixed $item): string =>
                        strtolower(
                            valueToText($item)
                        ),
                    (array)$condition['in']
                ),
                true
            )
        ) {
            return true;
        }

        if (
            isset($condition['gte']) &&
            is_numeric($value) &&
            (float)$value >=
            (float)$condition['gte']
        ) {
            return true;
        }
    }

    return false;
}

function collectValues(
    array $normalized,
    array $fields,
    int $limit
): array {
    $result = [];

    foreach ($fields as $field) {
        foreach (
            $normalized[$field] ?? []
            as $value
        ) {
            if (
                $value !== '' &&
                !in_array(
                    $value,
                    $result,
                    true
                )
            ) {
                $result[] = $value;
            }

            if (count($result) >= $limit) {
                return $result;
            }
        }
    }

    return $result;
}

function analyzeRecord(
    array $record,
    array $config
): array {
    $expanded = expandEmbeddedJson($record);
    $flat = flattenJson($expanded);
    $normalized = normalizeFields(
        $flat,
        $config
    );
    $searchText = createSearchText($flat);

    $events = [];

    foreach (
        $config['event_catalog'] ?? []
        as $id => $event
    ) {
        $condition = $event['when']
            ?? [
                'any_text' =>
                    $event['match'] ?? []
            ];

        if (
            matchesCondition(
                (array)$condition,
                $searchText,
                $normalized,
                []
            )
        ) {
            $events[] = [
                'id' => (string)$id
            ] + $event;
        }
    }

    $sources = [];

    foreach (
        $config['product_catalog'] ?? []
        as $id => $product
    ) {
        if (
            matchesCondition(
                (array)($product['when'] ?? []),
                $searchText,
                $normalized,
                $events
            )
        ) {
            $sources[] = (string)(
                $product['name'] ?? $id
            );
        }
    }

    $findings = [];

    foreach (
        $config['rules'] ?? []
        as $rule
    ) {
        if (
            ($rule['enabled'] ?? true) &&
            matchesCondition(
                (array)($rule['when'] ?? []),
                $searchText,
                $normalized,
                $events
            )
        ) {
            $findings[] = $rule;
        }
    }

    usort(
        $findings,
        static fn(array $a, array $b): int =>
            (int)($b['score'] ?? 0) <=>
            (int)($a['score'] ?? 0)
    );

    $score = min(
        100,
        max(
            0,
            (int)array_sum(
                array_column(
                    $findings,
                    'score'
                )
            )
        )
    );

    $severity = [
        'label' => 'Informativ',
        'color' => '#5f6368'
    ];

    foreach (
        $config['severity_levels'] ?? []
        as $level
    ) {
        if (
            $score >=
            (int)($level['min'] ?? 0) &&
            $score <=
            (int)($level['max'] ?? 100)
        ) {
            $severity = $level;
            break;
        }
    }

    $operation = collectValues(
        $normalized,
        ['operation', 'action'],
        1
    );

    return [
        'title' => (string)(
            $events[0]['title']
            ?? $operation[0]
            ?? 'Sicherheitsereignis'
        ),

        'summary' => (string)(
            $events[0]['summary']
            ?? 'Das Ereignis wurde verarbeitet.'
        ),

        'severity' => $severity,
        'score' => $score,

        'source' => array_slice(
            array_values(
                array_unique($sources)
            ),
            0,
            1
        ),

        'time' => collectValues(
            $normalized,
            [
                'timestamp',
                'event_time',
                'creation_time'
            ],
            1
        ),

        'users' => collectValues(
            $normalized,
            [
                'source_user',
                'destination_user',
                'user',
                'email',
                'display_name'
            ],
            3
        ),

        'systems' => collectValues(
            $normalized,
            [
                'source_host',
                'destination_host',
                'host',
                'device',
                'source_ip',
                'destination_ip',
                'ip'
            ],
            3
        ),

        'objects' => collectValues(
            $normalized,
            [
                'file_name',
                'url',
                'domain',
                'resource',
                'process'
            ],
            3
        ),

        'findings' => array_slice(
            $findings,
            0,
            2
        )
    ];
}

function mergeUniqueValues(
    array $analyses,
    string $field,
    int $limit
): array {
    $result = [];

    foreach ($analyses as $analysis) {
        foreach (
            $analysis[$field] ?? []
            as $value
        ) {
            if (
                !in_array(
                    $value,
                    $result,
                    true
                )
            ) {
                $result[] = $value;
            }

            if (count($result) >= $limit) {
                return $result;
            }
        }
    }

    return $result;
}

function mergeFindings(
    array $analyses,
    int $limit
): array {
    $findings = [];

    foreach ($analyses as $analysis) {
        foreach (
            $analysis['findings'] ?? []
            as $finding
        ) {
            $key =
                $finding['id']
                ?? $finding['title']
                ?? md5(
                    json_encode($finding)
                );

            $findings[$key] = $finding;
        }
    }

    $findings = array_values($findings);

    usort(
        $findings,
        static fn(array $a, array $b): int =>
            (int)($b['score'] ?? 0) <=>
            (int)($a['score'] ?? 0)
    );

    return array_slice(
        $findings,
        0,
        $limit
    );
}

$error = null;
$result = null;

try {
    $configFile = __DIR__ . '/data.json';

    if (!is_readable($configFile)) {
        throw new RuntimeException(
            'data.json fehlt oder ist nicht lesbar.'
        );
    }

    $config = json_decode(
        (string)file_get_contents($configFile),
        true,
        128,
        JSON_THROW_ON_ERROR |
        JSON_BIGINT_AS_STRING
    );

    if (
        ($_SERVER['REQUEST_METHOD'] ?? 'GET')
        === 'POST'
    ) {
        $input = (string)(
            $_POST['log'] ?? ''
        );

        decodeInvestigation($input);

        $basePath = strtok(
            $_SERVER['REQUEST_URI'],
            '?'
        );

        header(
            'Location: ' .
            $basePath .
            '?d=' .
            rawurlencode(
                encodeInvestigationState($input)
            )
        );

        exit;
    }

    if (isset($_GET['d'])) {
        $input = decodeInvestigationState(
            (string)$_GET['d']
        );

        $decoded = decodeInvestigation($input);

        $records = extractRecords(
            $decoded,
            $config
        );

        $analyses = [];

        foreach ($records as $record) {
            $analyses[] = analyzeRecord(
                is_array($record)
                    ? $record
                    : ['value' => $record],
                $config
            );
        }

        usort(
            $analyses,
            static fn(array $a, array $b): int =>
                $b['score'] <=> $a['score']
        );

        $primary = $analyses[0];

        $result = [
            'primary' => $primary,
            'event_count' => count($analyses),
            'users' => mergeUniqueValues(
                $analyses,
                'users',
                4
            ),
            'systems' => mergeUniqueValues(
                $analyses,
                'systems',
                4
            ),
            'objects' => mergeUniqueValues(
                $analyses,
                'objects',
                4
            ),
            'findings' => mergeFindings(
                $analyses,
                3
            )
        ];
    }
} catch (Throwable $exception) {
    $error = $exception->getMessage();
}

?>
<!doctype html>
<html lang="de">
<head>
    <meta charset="utf-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1"
    >

    <link
        rel="icon"
        href="./favicon.svg"
        type="image/svg+xml"
    >

    <title><?= $result === null
        ? 'IDR Investigation Analyzer'
        : 'Investigation'
    ?></title>

    <style>
        :root {
            color-scheme: dark;
            --background: #080808;
            --surface: #171717;
            --surface-highlight: #202020;
            --border: #343434;
            --text: #f2f2f2;
            --muted: #999999;
            --red: #d71920;
        }

        * {
            box-sizing: border-box;
        }

        html,
        body {
            min-height: 100%;
            margin: 0;
            background: var(--background);
            color: var(--text);
            font-family: Arial, sans-serif;
            font-size: 14px;
        }

        .start-page {
            min-height: 100vh;
            display: grid;
            place-items: center;
            padding: 28px;
        }

        .start-content {
            width: min(
                760px,
                calc(100vw - 40px)
            );
            text-align: left;
        }

        .start-content h1 {
            margin: 0 0 16px;
            font-size: 22px;
            font-weight: 700;
        }

        .start-content textarea {
            display: block;
            width: 100%;
            height: 280px;
            padding: 14px;
            resize: vertical;
            border: 1px solid var(--border);
            border-radius: 4px;
            outline: none;
            background: #121212;
            color: var(--text);
            font-family: Consolas, monospace;
            font-size: 13px;
            line-height: 1.45;
        }

        .start-content textarea:focus {
            border-color: var(--red);
            outline: 1px solid var(--red);
        }

        .start-content button {
            display: block;
            margin: 12px auto 0;
            padding: 10px 22px;
            border: 0;
            border-radius: 4px;
            background: var(--red);
            color: #ffffff;
            font-weight: 700;
            cursor: pointer;
        }

        .error {
            margin-top: 12px;
            color: #ff8e8e;
        }

        .result-page {
            min-height: 100vh;
            display: grid;
            align-content: center;
            padding: 18px 58px 18px 18px;
        }

        .trash {
            position: fixed;
            top: 14px;
            right: 14px;
            z-index: 10;
            display: grid;
            place-items: center;
            width: 34px;
            height: 34px;
            border: 1px solid var(--border);
            border-radius: 4px;
            background: #181818;
            color: #c8c8c8;
            text-decoration: none;
        }

        .trash:hover {
            border-color: #666666;
            color: #ffffff;
        }

        .trash svg {
            width: 19px;
            height: 19px;
        }

        .investigation {
            display: grid;
            grid-template-columns:
                minmax(220px, 0.85fr)
                minmax(280px, 1.15fr)
                minmax(280px, 1fr);
            gap: 10px;
            width: 100%;
            max-width: 1500px;
        }

        .card {
            min-width: 0;
            padding: 14px;
            overflow: hidden;
            border: 1px solid var(--border);
            border-radius: 4px;
            background: var(--surface);
        }

        .primary-card {
            background: var(--surface-highlight);
        }

        .event-title {
            margin-bottom: 8px;
            overflow: hidden;
            font-size: 18px;
            font-weight: 700;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .status {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 9px;
        }

        .severity {
            padding: 3px 7px;
            border-radius: 3px;
            color: #ffffff;
            font-weight: 700;
        }

        .score {
            color: var(--muted);
        }

        .summary {
            line-height: 1.4;
        }

        .row {
            padding: 7px 0;
            overflow: hidden;
            border-top: 1px solid #2c2c2c;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .summary + .row {
            margin-top: 8px;
        }

        .label {
            margin-bottom: 3px;
            color: var(--muted);
            font-size: 10px;
            letter-spacing: 0.07em;
            text-transform: uppercase;
        }

        .section-label {
            margin-bottom: 7px;
            color: #d5d5d5;
            font-size: 11px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .finding {
            line-height: 1.3;
            white-space: normal;
        }

        .finding strong {
            display: block;
            margin-bottom: 2px;
        }

        .empty {
            color: var(--muted);
        }

        @media (max-width: 900px) {
            .result-page {
                align-content: start;
                padding-top: 58px;
            }

            .investigation {
                grid-template-columns: 1fr 1fr;
            }

            .assessment {
                grid-column: 1 / -1;
            }
        }

        @media (max-width: 600px) {
            .start-page {
                place-items: start center;
                padding-top: 70px;
            }

            .start-content textarea {
                height: 240px;
            }

            .result-page {
                padding: 58px 12px 12px;
            }

            .investigation {
                grid-template-columns: 1fr;
            }

            .assessment {
                grid-column: auto;
            }
        }
    </style>
</head>

<body>

<?php if ($result === null): ?>

    <main class="start-page">
        <section class="start-content">
            <h1>IDR Investigation Analyzer</h1>

            <form method="post">
                <textarea
                    name="log"
                    spellcheck="false"
                    placeholder="Investigation json einfügen"
                    required
                ></textarea>

                <button type="submit">
                    AUSWERTEN
                </button>
            </form>

            <?php if ($error !== null): ?>
                <div class="error">
                    <?= escapeHtml($error) ?>
                </div>
            <?php endif; ?>
        </section>
    </main>

<?php else: ?>

    <?php $primary = $result['primary']; ?>

    <main class="result-page">

        <a
            class="trash"
            href="<?= escapeHtml(
                strtok(
                    $_SERVER['REQUEST_URI'],
                    '?'
                )
            ) ?>"
            aria-label="Investigation löschen"
            title="Investigation löschen"
        >
            <svg
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="1.8"
                stroke-linecap="round"
                stroke-linejoin="round"
                aria-hidden="true"
            >
                <path d="M4 7h16" />
                <path d="M9 7V4h6v3" />
                <path d="M7 7l1 13h8l1-13" />
                <path d="M10 11v5" />
                <path d="M14 11v5" />
            </svg>
        </a>

        <section class="investigation">

            <article class="card primary-card">
                <div class="event-title">
                    <?= escapeHtml(
                        $primary['title']
                    ) ?>
                </div>

                <div class="status">
                    <span
                        class="severity"
                        style="background:<?= escapeHtml(
                            $primary['severity']['color']
                            ?? '#666666'
                        ) ?>"
                    >
                        <?= escapeHtml(
                            $primary['severity']['label']
                            ?? 'Informativ'
                        ) ?>
                    </span>

                    <span class="score">
                        Score
                        <?= escapeHtml(
                            $primary['score']
                        ) ?>
                    </span>
                </div>

                <div class="summary">
                    <?= escapeHtml(
                        $primary['summary']
                    ) ?>
                </div>

                <?php if ($primary['source']): ?>
                    <div class="row">
                        <div class="label">
                            Quelle
                        </div>

                        <?= escapeHtml(
                            implode(
                                ' · ',
                                $primary['source']
                            )
                        ) ?>
                    </div>
                <?php endif; ?>

                <?php if ($primary['time']): ?>
                    <div class="row">
                        <div class="label">
                            Zeit
                        </div>

                        <?= escapeHtml(
                            $primary['time'][0]
                        ) ?>
                    </div>
                <?php endif; ?>

                <?php if (
                    $result['event_count'] > 1
                ): ?>
                    <div class="row">
                        <div class="label">
                            Korrelierte Ereignisse
                        </div>

                        <?= escapeHtml(
                            $result['event_count']
                        ) ?>
                    </div>
                <?php endif; ?>
            </article>

            <article class="card">
                <div class="section-label">
                    Beteiligte und Ziel
                </div>

                <?php if ($result['users']): ?>
                    <div class="row">
                        <div class="label">
                            Benutzer
                        </div>

                        <?= escapeHtml(
                            implode(
                                ' · ',
                                $result['users']
                            )
                        ) ?>
                    </div>
                <?php endif; ?>

                <?php if ($result['systems']): ?>
                    <div class="row">
                        <div class="label">
                            Systeme / Adressen
                        </div>

                        <?= escapeHtml(
                            implode(
                                ' · ',
                                $result['systems']
                            )
                        ) ?>
                    </div>
                <?php endif; ?>

                <?php if ($result['objects']): ?>
                    <div class="row">
                        <div class="label">
                            Objekte / Ressourcen
                        </div>

                        <?= escapeHtml(
                            implode(
                                ' · ',
                                $result['objects']
                            )
                        ) ?>
                    </div>
                <?php endif; ?>

                <?php if (
                    !$result['users'] &&
                    !$result['systems'] &&
                    !$result['objects']
                ): ?>
                    <div class="empty">
                        Keine weiteren relevanten
                        Entitäten erkannt.
                    </div>
                <?php endif; ?>
            </article>

            <article class="card assessment">
                <div class="section-label">
                    Bewertung
                </div>

                <?php foreach (
                    $result['findings']
                    as $finding
                ): ?>
                    <div class="row finding">
                        <strong>
                            <?= escapeHtml(
                                $finding['title']
                                ?? $finding['id']
                                ?? 'Treffer'
                            ) ?>
                        </strong>

                        <?= escapeHtml(
                            $finding['description']
                            ?? ''
                        ) ?>
                    </div>
                <?php endforeach; ?>

                <?php if (
                    !$result['findings']
                ): ?>
                    <div class="empty">
                        Keine regelbasierte
                        Auffälligkeit erkannt.
                    </div>
                <?php endif; ?>
            </article>

        </section>
    </main>

<?php endif; ?>

</body>
</html>
