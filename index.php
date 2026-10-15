<?php
declare(strict_types=1);

const MAX_INPUT_BYTES = 26214400;

function h(mixed $value): string {
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function valueText(mixed $value): string {
    if (is_bool($value)) return $value ? 'Ja' : 'Nein';
    if ($value === null) return '–';
    return is_scalar($value)
        ? trim((string)$value)
        : (json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?: '');
}

function decodeInvestigation(string $input): mixed {
    $input = trim($input);
    if ($input === '') throw new RuntimeException('Keine Investigation eingefügt.');
    if (strlen($input) > MAX_INPUT_BYTES) throw new RuntimeException('Die Investigation ist zu groß.');

    $decodedHtml = html_entity_decode($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $candidates = array_unique([$input, $decodedHtml, trim(strip_tags($decodedHtml))]);

    foreach ($candidates as $candidate) {
        $json = json_decode($candidate, true, 128, JSON_BIGINT_AS_STRING);
        if (json_last_error() === JSON_ERROR_NONE) return $json;
    }

    $rows = [];
    foreach (preg_split('/\R/u', $input) ?: [] as $line) {
        if (trim($line) === '') continue;
        $json = json_decode(trim($line), true, 128, JSON_BIGINT_AS_STRING);
        if (json_last_error() !== JSON_ERROR_NONE) {
            $rows = [];
            break;
        }
        $rows[] = $json;
    }
    if ($rows !== []) return $rows;

    throw new RuntimeException('Ungültiges JSON oder NDJSON.');
}

function expandEmbeddedJson(mixed $value, int $depth = 0): mixed {
    if ($depth > 8) return $value;

    if (is_array($value)) {
        foreach ($value as $key => $child) {
            $value[$key] = expandEmbeddedJson($child, $depth + 1);
        }
        return $value;
    }

    if (!is_string($value)) return $value;

    $candidate = trim(html_entity_decode(strip_tags($value), ENT_QUOTES | ENT_HTML5, 'UTF-8'));
    if (!in_array($candidate[0] ?? '', ['{', '['], true)) return $value;

    $json = json_decode($candidate, true, 128, JSON_BIGINT_AS_STRING);
    return json_last_error() === JSON_ERROR_NONE
        ? expandEmbeddedJson($json, $depth + 1)
        : $value;
}

function flatten(mixed $value, string $path = '', array &$result = []): array {
    if (is_array($value)) {
        foreach ($value as $key => $child) {
            flatten($child, $path === '' ? (string)$key : $path . '.' . $key, $result);
        }
    } else {
        $result[$path === '' ? '$' : $path] = $value;
    }
    return $result;
}

function encodeState(string $input): string {
    return rtrim(strtr(base64_encode(gzdeflate($input, 9)), '+/', '-_'), '=');
}

function decodeState(string $state): string {
    $padding = strlen($state) % 4;
    if ($padding !== 0) $state .= str_repeat('=', 4 - $padding);
    $decoded = base64_decode(strtr($state, '-_', '+/'), true);
    $inflated = $decoded === false ? false : @gzinflate($decoded);
    if ($inflated === false) throw new RuntimeException('Die Investigation im Link ist ungültig.');
    return $inflated;
}

function normalize(array $flat, array $config): array {
    $normalized = [];

    foreach ($config['field_aliases'] ?? [] as $canonical => $definition) {
        $aliases = $definition['aliases'] ?? $definition;

        foreach ($flat as $path => $value) {
            $leaf = strtolower((string)preg_replace('/.*\./', '', $path));
            $compactPath = strtolower((string)preg_replace('/[^a-z0-9]+/i', '', $path));

            foreach ((array)$aliases as $alias) {
                $alias = strtolower((string)$alias);
                $compactAlias = strtolower((string)preg_replace('/[^a-z0-9]+/i', '', $alias));

                if ($leaf === $alias || ($compactAlias !== '' && str_ends_with($compactPath, $compactAlias))) {
                    $text = valueText($value);
                    if ($text !== '' && !in_array($text, $normalized[(string)$canonical] ?? [], true)) {
                        $normalized[(string)$canonical][] = $text;
                    }
                    break;
                }
            }
        }
    }

    return $normalized;
}

function searchable(array $flat): string {
    $parts = [];
    foreach ($flat as $path => $value) $parts[] = $path . '=' . valueText($value);
    return strtolower(implode("\n", $parts));
}

function matchesCondition(array $condition, string $haystack, array $normalized, array $events): bool {
    if ($condition === []) return false;

    if (isset($condition['all'])) {
        foreach ($condition['all'] as $part) {
            if (!matchesCondition((array)$part, $haystack, $normalized, $events)) return false;
        }
        return true;
    }

    if (isset($condition['any'])) {
        foreach ($condition['any'] as $part) {
            if (matchesCondition((array)$part, $haystack, $normalized, $events)) return true;
        }
        return false;
    }

    if (isset($condition['not'])) {
        return !matchesCondition((array)$condition['not'], $haystack, $normalized, $events);
    }

    if (isset($condition['event'])) {
        return in_array((string)$condition['event'], array_column($events, 'id'), true);
    }

    if (isset($condition['any_text'])) {
        foreach ((array)$condition['any_text'] as $needle) {
            if ($needle !== '' && str_contains($haystack, strtolower((string)$needle))) return true;
        }
        return false;
    }

    if (isset($condition['all_text'])) {
        foreach ((array)$condition['all_text'] as $needle) {
            if (!str_contains($haystack, strtolower((string)$needle))) return false;
        }
        return true;
    }

    if (isset($condition['field'])) {
        $values = $normalized[(string)$condition['field']] ?? [];

        if (array_key_exists('exists', $condition)) {
            return (bool)$condition['exists'] === ($values !== []);
        }

        foreach ($values as $value) {
            $lower = strtolower($value);
            if (array_key_exists('equals', $condition) && $lower === strtolower(valueText($condition['equals']))) return true;
            if (isset($condition['contains']) && str_contains($lower, strtolower((string)$condition['contains']))) return true;
            if (isset($condition['in']) && in_array($lower, array_map(fn($v) => strtolower(valueText($v)), (array)$condition['in']), true)) return true;
            if (isset($condition['gte']) && is_numeric($value) && (float)$value >= (float)$condition['gte']) return true;
        }
    }

    return false;
}

function take(array $normalized, array $fields, int $limit): array {
    $result = [];
    foreach ($fields as $field) {
        foreach ($normalized[$field] ?? [] as $value) {
            if ($value !== '' && !in_array($value, $result, true)) $result[] = $value;
            if (count($result) >= $limit) return $result;
        }
    }
    return $result;
}

function recordsFrom(mixed $decoded, array $config): array {
    if (!is_array($decoded)) return [['value' => $decoded]];
    if (array_is_list($decoded)) return $decoded === [] ? [[]] : $decoded;

    foreach ($config['record_containers'] ?? [] as $path) {
        $current = $decoded;
        foreach (explode('.', (string)$path) as $segment) {
            if (!is_array($current) || !array_key_exists($segment, $current)) continue 2;
            $current = $current[$segment];
        }
        if (is_array($current) && array_is_list($current) && $current !== []) return $current;
    }

    return [$decoded];
}

function analyzeRecord(array $record, array $config): array {
    $expanded = expandEmbeddedJson($record);
    $flat = flatten($expanded);
    $normalized = normalize($flat, $config);
    $haystack = searchable($flat);

    $events = [];
    foreach ($config['event_catalog'] ?? [] as $id => $event) {
        $condition = $event['when'] ?? ['any_text' => $event['match'] ?? []];
        if (matchesCondition((array)$condition, $haystack, $normalized, [])) {
            $events[] = ['id' => (string)$id] + $event;
        }
    }

    $sources = [];
    foreach ($config['product_catalog'] ?? [] as $id => $product) {
        if (matchesCondition((array)($product['when'] ?? []), $haystack, $normalized, $events)) {
            $sources[] = (string)($product['name'] ?? $id);
        }
    }

    $findings = [];
    foreach ($config['rules'] ?? [] as $rule) {
        if (($rule['enabled'] ?? true) && matchesCondition((array)($rule['when'] ?? []), $haystack, $normalized, $events)) {
            $findings[] = $rule;
        }
    }
    usort($findings, fn($a, $b) => (int)($b['score'] ?? 0) <=> (int)($a['score'] ?? 0));

    $score = min(100, max(0, (int)array_sum(array_column($findings, 'score'))));
    $severity = ['label' => 'Informativ', 'color' => '#5f6368'];
    foreach ($config['severity_levels'] ?? [] as $level) {
        if ($score >= (int)($level['min'] ?? 0) && $score <= (int)($level['max'] ?? 100)) {
            $severity = $level;
            break;
        }
    }

    return [
        'title' => (string)($events[0]['title'] ?? take($normalized, ['operation', 'action'], 1)[0] ?? 'Sicherheitsereignis'),
        'summary' => (string)($events[0]['summary'] ?? 'Das Ereignis wurde verarbeitet.'),
        'severity' => $severity,
        'score' => $score,
        'source' => array_slice(array_values(array_unique($sources)), 0, 3),
        'time' => take($normalized, ['timestamp', 'event_time', 'creation_time'], 1),
        'users' => take($normalized, ['source_user', 'destination_user', 'user', 'email', 'display_name'], 6),
        'systems' => take($normalized, ['source_host', 'destination_host', 'host', 'device', 'source_ip', 'destination_ip', 'ip'], 6),
        'objects' => take($normalized, ['file_name', 'file_path', 'url', 'domain', 'resource', 'process', 'command_line'], 6),
        'context' => take($normalized, ['service', 'communication_type', 'workload', 'category', 'status', 'participating_domain', 'tenant_name', 'tenant_id', 'country', 'city', 'rule_name'], 8),
        'findings' => array_slice($findings, 0, 4)
    ];
}

$error = null;
$result = null;

try {
    $configFile = __DIR__ . '/data.json';
    if (!is_readable($configFile)) throw new RuntimeException('data.json fehlt oder ist nicht lesbar.');
    $config = json_decode((string)file_get_contents($configFile), true, 128, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $input = (string)($_POST['log'] ?? '');
        decodeInvestigation($input);
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?') . '?inv=' . rawurlencode(encodeState($input)));
        exit;
    }

    if (isset($_GET['inv'])) {
        $input = decodeState((string)$_GET['inv']);
        $decoded = decodeInvestigation($input);
        $records = recordsFrom($decoded, $config);
        $analyses = [];
        foreach ($records as $record) {
            $analyses[] = analyzeRecord(is_array($record) ? $record : ['value' => $record], $config);
        }

        usort($analyses, fn($a, $b) => $b['score'] <=> $a['score']);
        $primary = $analyses[0];

        $result = [
            'primary' => $primary,
            'event_count' => count($analyses),
            'users' => array_slice(array_values(array_unique(array_merge(...array_column($analyses, 'users')))), 0, 6),
            'systems' => array_slice(array_values(array_unique(array_merge(...array_column($analyses, 'systems')))), 0, 6),
            'objects' => array_slice(array_values(array_unique(array_merge(...array_column($analyses, 'objects')))), 0, 6),
            'context' => array_slice(array_values(array_unique(array_merge(...array_map(static fn(array $a): array => $a['context'] ?? [], $analyses)))), 0, 6),
            'findings' => array_slice(array_values(array_reduce($analyses, function($carry, $item) {
                foreach ($item['findings'] as $finding) $carry[$finding['id'] ?? $finding['title'] ?? md5(json_encode($finding))] = $finding;
                return $carry;
            }, [])), 0, 4)
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
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" href="./favicon.svg" type="image/svg+xml">
<title>IDR INV Analyzer</title>
<style>
:root{color-scheme:dark;--bg:#090909;--surface:#171717;--surface2:#202020;--line:#353535;--text:#f3f3f3;--muted:#a5a5a5;--red:#d71920}*{box-sizing:border-box}html,body{margin:0;min-height:100%;background:var(--bg);color:var(--text);font:14px Arial,sans-serif}.start{min-height:100vh;display:grid;place-items:center;padding:24px}.start-inner{width:min(820px,calc(100vw - 40px))}.start h1{margin:0 0 16px;font-size:22px}.start textarea{display:block;width:100%;height:300px;padding:14px;border:1px solid var(--line);border-radius:4px;outline:0;background:#131313;color:var(--text);font:13px/1.5 Consolas,monospace;resize:vertical}.start textarea:focus{border-color:var(--red);box-shadow:0 0 0 1px var(--red)}.start button{display:block;margin:12px auto 0;padding:10px 22px;border:0;border-radius:4px;background:var(--red);color:#fff;font-weight:700;cursor:pointer}.error{margin-top:12px;color:#ff9696}.result{min-height:100vh;display:grid;place-items:center;padding:54px 58px 30px 30px}.trash{position:fixed;top:14px;right:14px;z-index:5;display:grid;place-items:center;width:34px;height:34px;border:1px solid var(--line);border-radius:4px;background:#181818;color:#ccc;text-decoration:none}.trash:hover{color:#fff;border-color:#666}.trash svg{width:19px;height:19px}.investigation{display:grid;grid-template-columns:minmax(300px,.9fr) minmax(420px,1.35fr);gap:12px;width:min(1180px,100%);align-items:stretch}.card{min-width:0;padding:16px;border:1px solid var(--line);border-radius:5px;background:var(--surface)}.main-card{background:var(--surface2)}.title{margin-bottom:8px;font-size:19px;font-weight:700;overflow-wrap:anywhere}.status{display:flex;align-items:center;gap:8px;margin-bottom:10px}.severity{padding:3px 7px;border-radius:3px;color:#fff;font-weight:700}.score{color:var(--muted)}.summary{line-height:1.45}.row{padding:8px 0;border-top:1px solid #303030;overflow-wrap:anywhere}.summary+.row{margin-top:9px}.label,.section-label{color:var(--muted);font-size:10px;letter-spacing:.07em;text-transform:uppercase}.label{margin-bottom:5px}.section-label{margin-bottom:9px;color:#ddd}.values{display:flex;flex-wrap:wrap;gap:5px}.value{display:inline-block;max-width:100%;padding:4px 7px;border:1px solid #404040;border-radius:3px;background:#262626;line-height:1.25;overflow-wrap:anywhere}.finding{line-height:1.4}.finding b{display:block;margin-bottom:2px}.empty{color:var(--muted)}@media(max-width:820px){.result{place-items:start;padding:54px 12px 20px}.investigation{grid-template-columns:1fr}}@media(max-width:600px){.start{place-items:start center;padding-top:60px}.start textarea{height:250px}}
</style>
</head>
<body>
<?php if ($result === null): ?>
<main class="start">
  <section class="start-inner">
    <h1>IDR Investigation Analyzer</h1>
    <form method="post">
      <textarea name="log" spellcheck="false" placeholder="Investigation json einfügen" required></textarea>
      <button type="submit">AUSWERTEN</button>
    </form>
    <?php if ($error !== null): ?><div class="error"><?=h($error)?></div><?php endif; ?>
  </section>
</main>
<?php else: $primary = $result['primary']; ?>
<main class="result">
  <a class="trash" href="<?=h(strtok($_SERVER['REQUEST_URI'], '?'))?>" aria-label="Investigation löschen" title="Investigation löschen">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 7h16M9 7V4h6v3m-8 0 1 13h8l1-13M10 11v5m4-5v5"/></svg>
  </a>

  <section class="investigation">
    <article class="card main-card">
      <div class="title"><?=h($primary['title'])?></div>
      <div class="status">
        <span class="severity" style="background:<?=h($primary['severity']['color'] ?? '#666')?>"><?=h($primary['severity']['label'] ?? 'Informativ')?></span>
        <span class="score">Score <?=h($primary['score'])?></span>
      </div>
      <div class="summary"><?=h($primary['summary'])?></div>
      <?php if ($primary['source']): ?><div class="row"><div class="label">Quelle</div><?=h(implode(' · ', $primary['source']))?></div><?php endif; ?>
      <?php if ($primary['time']): ?><div class="row"><div class="label">Zeit</div><?=h($primary['time'][0])?></div><?php endif; ?>
      <?php if ($result['event_count'] > 1): ?><div class="row"><div class="label">Korrelierte Ereignisse</div><?=h($result['event_count'])?></div><?php endif; ?>
    </article>

    <article class="card">
      <div class="section-label">Beteiligte und Ziel</div>
      <?php if ($result['users']): ?><div class="row"><div class="label">Benutzer</div><div class="values"><?php foreach($result['users'] as $value): ?><span class="value"><?=h($value)?></span><?php endforeach; ?></div></div><?php endif; ?>
      <?php if ($result['systems']): ?><div class="row"><div class="label">Systeme / Adressen</div><div class="values"><?php foreach($result['systems'] as $value): ?><span class="value"><?=h($value)?></span><?php endforeach; ?></div></div><?php endif; ?>
      <?php if ($result['objects']): ?><div class="row"><div class="label">Objekte / Ressourcen</div><div class="values"><?php foreach($result['objects'] as $value): ?><span class="value"><?=h($value)?></span><?php endforeach; ?></div></div><?php endif; ?>
      <?php if (!$result['users'] && !$result['systems'] && !$result['objects']): ?><div class="empty">Keine weiteren relevanten Entitäten erkannt.</div><?php endif; ?>
    </article>

    <article class="card">
      <div class="section-label">Kontext</div>
      <?php if ($result['context']): ?><div class="row"><div class="label">Dienst / Status / Tenant</div><div class="values"><?php foreach($result['context'] as $value): ?><span class="value"><?=h($value)?></span><?php endforeach; ?></div></div><?php else: ?><div class="empty">Kein zusätzlicher Kontext erkannt.</div><?php endif; ?>
    </article>

    <article class="card assessment">
      <div class="section-label">Bewertung</div>
      <?php foreach ($result['findings'] as $finding): ?>
        <div class="row finding"><b><?=h($finding['title'] ?? $finding['id'] ?? 'Treffer')?></b><?=h($finding['description'] ?? '')?></div>
      <?php endforeach; ?>
      <?php if (!$result['findings']): ?><div class="empty">Keine regelbasierte Auffälligkeit erkannt.</div><?php endif; ?>
    </article>
  </section>
</main>
<?php endif; ?>
</body>
</html>
