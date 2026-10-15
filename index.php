<?php
declare(strict_types=1);

const MAX_INPUT_BYTES = 25 * 1024 * 1024;
const MAX_DEPTH = 128;
const MAX_NODES = 250000;

final class InvestigationAnalyzer
{
    private array $cfg;
    private int $nodeCount = 0;

    public function __construct(array $config)
    {
        $this->cfg = $config;
    }

    public function analyze(string $input): array
    {
        $decoded = $this->decodeInput($input);
        $records = $this->records($decoded);
        $analyses = [];

        foreach ($records as $index => $record) {
            $analyses[] = $this->analyzeRecord($record, $index);
        }

        return [
            'input_format' => $this->detectFormat($input),
            'record_count' => count($analyses),
            'records' => $analyses,
            'aggregate' => $this->aggregate($analyses),
        ];
    }

    private function decodeInput(string $input): mixed
    {
        $input = trim($input);
        if ($input === '') {
            throw new RuntimeException($this->text('errors.empty_input', 'Kein Log übergeben.'));
        }
        if (strlen($input) > MAX_INPUT_BYTES) {
            throw new RuntimeException($this->text('errors.input_too_large', 'Die Eingabe überschreitet die zulässige Größe.'));
        }

        $candidates = [$input];
        $htmlDecoded = html_entity_decode($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        if ($htmlDecoded !== $input) {
            $candidates[] = $htmlDecoded;
        }
        $withoutTags = trim(strip_tags($htmlDecoded));
        if ($withoutTags !== '' && $withoutTags !== $htmlDecoded) {
            $candidates[] = $withoutTags;
        }

        foreach (array_values(array_unique($candidates)) as $candidate) {
            $decoded = json_decode($candidate, true, MAX_DEPTH, JSON_BIGINT_AS_STRING);
            if (json_last_error() === JSON_ERROR_NONE) {
                return $decoded;
            }
        }

        $lines = preg_split('/\R/u', $withoutTags !== '' ? $withoutTags : $input) ?: [];
        $items = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            $item = json_decode($line, true, MAX_DEPTH, JSON_BIGINT_AS_STRING);
            if (json_last_error() !== JSON_ERROR_NONE) {
                $items = [];
                break;
            }
            $items[] = $item;
        }
        if ($items !== []) {
            return $items;
        }

        throw new RuntimeException($this->text('errors.invalid_json', 'Ungültiges JSON oder NDJSON: ') . json_last_error_msg());
    }

    private function detectFormat(string $input): string
    {
        $trimmed = ltrim($input);
        if (str_contains($input, "\n") && !str_starts_with($trimmed, '[')) {
            $valid = 0;
            foreach (preg_split('/\R/u', $input) ?: [] as $line) {
                if (trim($line) === '') continue;
                json_decode(trim($line), true);
                if (json_last_error() === JSON_ERROR_NONE) $valid++;
            }
            if ($valid > 1) return 'ndjson';
        }
        return str_starts_with($trimmed, '[') ? 'json-array' : 'json';
    }

    private function records(mixed $decoded): array
    {
        if (!is_array($decoded)) {
            return [['value' => $decoded]];
        }
        if (array_is_list($decoded)) {
            return $decoded === [] ? [[]] : array_map(fn($v) => is_array($v) ? $v : ['value' => $v], $decoded);
        }
        foreach ($this->cfg['record_containers'] ?? [] as $path) {
            $value = $this->getPath($decoded, (string)$path);
            if (is_array($value) && array_is_list($value) && $value !== []) {
                return array_map(fn($v) => is_array($v) ? $v : ['value' => $v], $value);
            }
        }
        return [$decoded];
    }

    private function analyzeRecord(array $record, int $index): array
    {
        $this->nodeCount = 0;
        $expanded = $this->expandEmbedded($record);
        $flat = [];
        $this->flatten($expanded, '', $flat);
        $normalized = $this->normalize($flat);
        $entities = $this->extractEntities($flat, $normalized);
        $events = $this->detectCatalogItems($flat, $normalized, 'event_catalog');
        $products = $this->detectCatalogItems($flat, $normalized, 'product_catalog');
        $findings = $this->evaluateRules($expanded, $flat, $normalized, $entities, $events);
        $score = $this->score($findings);
        $severity = $this->severity($score, $normalized, $findings);
        $timeline = $this->timeline($flat, $normalized, $events);
        $mitre = $this->mitre($flat, $normalized, $findings, $events);
        $relationships = $this->relationships($entities, $normalized);
        $summary = $this->summary($normalized, $entities, $events, $products, $findings, $severity);

        return [
            'index' => $index + 1,
            'summary' => $summary,
            'severity' => $severity,
            'score' => $score,
            'events' => $events,
            'products' => $products,
            'normalized' => $normalized,
            'entities' => $entities,
            'relationships' => $relationships,
            'timeline' => $timeline,
            'findings' => $findings,
            'mitre' => $mitre,
            'raw_fields' => $flat,
        ];
    }

    private function expandEmbedded(mixed $value, int $depth = 0): mixed
    {
        if ($depth > 8) return $value;
        if (is_array($value)) {
            $out = [];
            foreach ($value as $k => $v) $out[$k] = $this->expandEmbedded($v, $depth + 1);
            return $out;
        }
        if (!is_string($value)) return $value;
        $trimmed = trim(html_entity_decode(strip_tags($value), ENT_QUOTES | ENT_HTML5, 'UTF-8'));
        if (($trimmed[0] ?? '') !== '{' && ($trimmed[0] ?? '') !== '[') return $value;
        $decoded = json_decode($trimmed, true, MAX_DEPTH, JSON_BIGINT_AS_STRING);
        return json_last_error() === JSON_ERROR_NONE ? $this->expandEmbedded($decoded, $depth + 1) : $value;
    }

    private function flatten(mixed $value, string $path, array &$out): void
    {
        if (++$this->nodeCount > MAX_NODES) throw new RuntimeException($this->text('errors.too_many_nodes', 'Der Log enthält zu viele Elemente.'));
        if (is_array($value)) {
            if ($value === []) $out[$path === '' ? '$' : $path] = [];
            foreach ($value as $k => $v) {
                $segment = (string)$k;
                $next = $path === '' ? $segment : $path . '.' . $segment;
                $this->flatten($v, $next, $out);
            }
            return;
        }
        $out[$path === '' ? '$' : $path] = $value;
    }

    private function normalize(array $flat): array
    {
        $result = [];
        foreach ($this->cfg['field_aliases'] ?? [] as $canonical => $definition) {
            $aliases = is_array($definition) && isset($definition['aliases']) ? $definition['aliases'] : $definition;
            $type = is_array($definition) ? ($definition['type'] ?? 'string') : 'string';
            $values = [];
            foreach ($flat as $path => $value) {
                $leaf = strtolower((string)preg_replace('/.*\./', '', $path));
                $normalizedPath = strtolower(preg_replace('/[^a-z0-9]+/i', '', $path) ?? $path);
                foreach ((array)$aliases as $alias) {
                    $a = strtolower((string)$alias);
                    $aNorm = strtolower(preg_replace('/[^a-z0-9]+/i', '', $a) ?? $a);
                    if ($leaf === $a || $normalizedPath === $aNorm || str_ends_with($normalizedPath, $aNorm)) {
                        $values[] = ['path' => $path, 'value' => $this->cast($value, $type)];
                        break;
                    }
                }
            }
            if ($values !== []) $result[(string)$canonical] = $this->uniquePairs($values);
        }
        return $result;
    }

    private function cast(mixed $value, string $type): mixed
    {
        return match ($type) {
            'bool', 'boolean' => filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE) ?? $value,
            'int', 'integer' => is_numeric($value) ? (int)$value : $value,
            'float', 'number' => is_numeric($value) ? (float)$value : $value,
            'datetime' => $this->dateValue($value),
            default => is_scalar($value) || $value === null ? $value : json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
        };
    }

    private function dateValue(mixed $value): mixed
    {
        if (!is_scalar($value)) return $value;
        $s = (string)$value;
        if (ctype_digit($s) && strlen($s) >= 10) {
            $n = (int)$s;
            if ($n > 9999999999) $n = intdiv($n, 1000);
            return gmdate('c', $n);
        }
        $ts = strtotime($s);
        return $ts === false ? $value : gmdate('c', $ts);
    }

    private function extractEntities(array $flat, array $normalized): array
    {
        $entities = [];
        foreach ($this->cfg['entity_patterns'] ?? [] as $type => $definition) {
            $patterns = $definition['patterns'] ?? $definition;
            $exclude = array_map('strtolower', (array)($definition['exclude'] ?? []));
            foreach ($flat as $path => $raw) {
                if (!is_scalar($raw) || $raw === '') continue;
                foreach ((array)$patterns as $pattern) {
                    $regex = $this->regex((string)$pattern);
                    if ($regex === null || @preg_match_all($regex, (string)$raw, $m) === false) continue;
                    foreach ($m[1] ?? $m[0] ?? [] as $match) {
                        $match = trim((string)$match, " \t\n\r\0\x0B.,;:()[]{}<>\"'");
                        if ($match === '' || in_array(strtolower($match), $exclude, true)) continue;
                        $entities[(string)$type][] = ['value' => $match, 'path' => $path, 'confidence' => (int)($definition['confidence'] ?? 70)];
                    }
                }
            }
        }
        foreach ($this->cfg['entity_fields'] ?? [] as $type => $fields) {
            foreach ((array)$fields as $field) {
                foreach ($normalized[(string)$field] ?? [] as $item) {
                    if (is_scalar($item['value']) && (string)$item['value'] !== '') {
                        $entities[(string)$type][] = ['value' => (string)$item['value'], 'path' => $item['path'], 'confidence' => 95];
                    }
                }
            }
        }
        foreach ($entities as $type => $items) $entities[$type] = $this->uniqueEntities($items);
        ksort($entities);
        return $entities;
    }

    private function detectCatalogItems(array $flat, array $normalized, string $section): array
    {
        $found = [];
        foreach ($this->cfg[$section] ?? [] as $id => $item) {
            if ($this->condition($item['when'] ?? ['any_text' => $item['match'] ?? []], $flat, $normalized, [], [])) {
                $found[] = ['id' => (string)$id] + $item;
            }
        }
        return $found;
    }

    private function evaluateRules(array $tree, array $flat, array $normalized, array $entities, array $events): array
    {
        $findings = [];
        foreach ($this->cfg['rules'] ?? [] as $index => $rule) {
            if (($rule['enabled'] ?? true) !== true) continue;
            if ($this->condition($rule['when'] ?? [], $flat, $normalized, $entities, $events, $tree)) {
                $findings[] = [
                    'id' => (string)($rule['id'] ?? 'rule-' . ($index + 1)),
                    'title' => (string)($rule['title'] ?? 'Treffer'),
                    'description' => (string)($rule['description'] ?? ''),
                    'category' => (string)($rule['category'] ?? 'general'),
                    'score' => (int)($rule['score'] ?? 0),
                    'severity' => $rule['severity'] ?? null,
                    'tags' => array_values((array)($rule['tags'] ?? [])),
                    'mitre' => array_values((array)($rule['mitre'] ?? [])),
                ];
            }
        }
        usort($findings, fn($a, $b) => $b['score'] <=> $a['score']);
        return $findings;
    }

    private function condition(array $c, array $flat, array $normalized, array $entities, array $events, array $tree = []): bool
    {
        if ($c === []) return false;
        if (isset($c['all'])) foreach ((array)$c['all'] as $x) if (!$this->condition((array)$x, $flat, $normalized, $entities, $events, $tree)) return false;
        if (isset($c['all']) && count((array)$c['all']) > 0) return true;
        if (isset($c['any'])) {
            foreach ((array)$c['any'] as $x) if ($this->condition((array)$x, $flat, $normalized, $entities, $events, $tree)) return true;
            return false;
        }
        if (isset($c['not'])) return !$this->condition((array)$c['not'], $flat, $normalized, $entities, $events, $tree);

        $haystack = strtolower(implode("\n", array_map(fn($k, $v) => $k . '=' . $this->scalar($v), array_keys($flat), $flat)));
        if (isset($c['any_text'])) {
            foreach ((array)$c['any_text'] as $needle) if ($needle !== '' && str_contains($haystack, strtolower((string)$needle))) return true;
            return false;
        }
        if (isset($c['all_text'])) {
            foreach ((array)$c['all_text'] as $needle) if ($needle === '' || !str_contains($haystack, strtolower((string)$needle))) return false;
            return true;
        }
        if (isset($c['regex'])) {
            $r = $this->regex((string)$c['regex']);
            return $r !== null && @preg_match($r, $haystack) === 1;
        }
        if (isset($c['path_exists'])) {
            foreach ((array)$c['path_exists'] as $pattern) foreach ($flat as $path => $_) if ($this->glob((string)$pattern, $path)) return true;
            return false;
        }
        if (isset($c['field'])) {
            $field = (string)$c['field'];
            $values = array_column($normalized[$field] ?? [], 'value');
            if (array_key_exists('exists', $c)) return (bool)$c['exists'] === ($values !== []);
            foreach ($values as $v) {
                if (array_key_exists('equals', $c) && strtolower($this->scalar($v)) === strtolower($this->scalar($c['equals']))) return true;
                if (isset($c['in']) && in_array(strtolower($this->scalar($v)), array_map(fn($x) => strtolower($this->scalar($x)), (array)$c['in']), true)) return true;
                if (isset($c['contains']) && str_contains(strtolower($this->scalar($v)), strtolower((string)$c['contains']))) return true;
                if (isset($c['matches'])) { $r = $this->regex((string)$c['matches']); if ($r && @preg_match($r, $this->scalar($v)) === 1) return true; }
                if (isset($c['gt']) && is_numeric($v) && (float)$v > (float)$c['gt']) return true;
                if (isset($c['gte']) && is_numeric($v) && (float)$v >= (float)$c['gte']) return true;
                if (isset($c['lt']) && is_numeric($v) && (float)$v < (float)$c['lt']) return true;
                if (isset($c['lte']) && is_numeric($v) && (float)$v <= (float)$c['lte']) return true;
            }
            return false;
        }
        if (isset($c['entity'])) {
            $count = count($entities[(string)$c['entity']] ?? []);
            return $count >= (int)($c['min'] ?? 1) && $count <= (int)($c['max'] ?? PHP_INT_MAX);
        }
        if (isset($c['event'])) return in_array((string)$c['event'], array_column($events, 'id'), true);
        return false;
    }

    private function score(array $findings): int
    {
        $sum = array_sum(array_column($findings, 'score'));
        $mode = $this->cfg['scoring']['mode'] ?? 'sum';
        if ($mode === 'max') $sum = $findings === [] ? 0 : max(array_column($findings, 'score'));
        return max((int)($this->cfg['scoring']['minimum'] ?? 0), min((int)($this->cfg['scoring']['maximum'] ?? 100), (int)$sum));
    }

    private function severity(int $score, array $normalized, array $findings): array
    {
        $forced = array_values(array_filter(array_column($findings, 'severity')));
        if ($forced !== []) {
            $order = array_flip(array_keys($this->cfg['severity_levels'] ?? []));
            usort($forced, fn($a, $b) => ($order[$b] ?? -1) <=> ($order[$a] ?? -1));
        }
        foreach ($this->cfg['severity_levels'] ?? [] as $id => $level) {
            if ($score >= (int)($level['min'] ?? 0) && $score <= (int)($level['max'] ?? PHP_INT_MAX)) {
                return ['id' => (string)$id, 'label' => (string)($level['label'] ?? $id), 'color' => (string)($level['color'] ?? '#64748b')];
            }
        }
        return ['id' => 'unknown', 'label' => 'Unbekannt', 'color' => '#64748b'];
    }

    private function timeline(array $flat, array $normalized, array $events): array
    {
        $items = [];
        foreach ((array)($this->cfg['timeline_fields'] ?? ['timestamp']) as $field) {
            foreach ($normalized[(string)$field] ?? [] as $time) {
                $items[] = ['time' => $time['value'], 'path' => $time['path'], 'event' => $events[0]['summary'] ?? $events[0]['title'] ?? 'Ereignis'];
            }
        }
        usort($items, fn($a, $b) => strcmp((string)$a['time'], (string)$b['time']));
        return $this->uniquePairs($items);
    }

    private function mitre(array $flat, array $normalized, array $findings, array $events): array
    {
        $ids = [];
        foreach ($findings as $f) foreach ($f['mitre'] as $id) $ids[] = (string)$id;
        foreach ($events as $e) foreach ((array)($e['mitre'] ?? []) as $id) $ids[] = (string)$id;
        $result = [];
        foreach (array_values(array_unique($ids)) as $id) $result[] = ['id' => $id] + ($this->cfg['mitre_catalog'][$id] ?? []);
        return $result;
    }

    private function relationships(array $entities, array $normalized): array
    {
        $out = [];
        foreach ($this->cfg['relationship_rules'] ?? [] as $r) {
            $from = $entities[(string)($r['from_entity'] ?? '')] ?? [];
            $to = $entities[(string)($r['to_entity'] ?? '')] ?? [];
            foreach ($from as $a) foreach ($to as $b) if ($a['value'] !== $b['value']) $out[] = ['from' => $a['value'], 'type' => (string)($r['type'] ?? 'related_to'), 'to' => $b['value']];
        }
        return $this->uniquePairs($out);
    }

    private function summary(array $normalized, array $entities, array $events, array $products, array $findings, array $severity): string
    {
        $parts = [];
        if ($events !== []) $parts[] = (string)($events[0]['summary'] ?? $events[0]['title'] ?? $events[0]['id']);
        else {
            $action = $normalized['action'][0]['value'] ?? $normalized['operation'][0]['value'] ?? null;
            $parts[] = $action ? 'Ereignis „' . $this->scalar($action) . '“ erkannt' : $this->text('texts.generic_event', 'Generisches Ereignis erkannt');
        }
        if ($products !== []) $parts[] = 'Quelle: ' . (string)($products[0]['name'] ?? $products[0]['id']);
        foreach ($this->cfg['summary_entities'] ?? ['user', 'host', 'ip', 'domain'] as $type) {
            $count = count($entities[(string)$type] ?? []);
            if ($count > 0) $parts[] = $count . ' ' . $this->entityLabel((string)$type, $count);
        }
        if ($findings === []) $parts[] = $this->text('texts.no_findings', 'Keine regelbasierten Auffälligkeiten erkannt');
        else $parts[] = count($findings) . ' Bewertungstreffer';
        $parts[] = 'Risiko: ' . $severity['label'];
        return implode('. ', array_filter($parts)) . '.';
    }

    private function aggregate(array $records): array
    {
        $scores = array_column($records, 'score');
        $findings = [];
        $entities = [];
        foreach ($records as $r) {
            foreach ($r['findings'] as $f) $findings[$f['id']] = $f;
            foreach ($r['entities'] as $type => $items) foreach ($items as $item) $entities[$type][] = $item;
        }
        foreach ($entities as $type => $items) $entities[$type] = $this->uniqueEntities($items);
        $max = $scores === [] ? 0 : max($scores);
        return ['max_score' => $max, 'severity' => $this->severity($max, [], array_values($findings)), 'findings' => array_values($findings), 'entities' => $entities];
    }

    private function getPath(array $data, string $path): mixed
    {
        $current = $data;
        foreach (explode('.', $path) as $part) {
            if (!is_array($current) || !array_key_exists($part, $current)) return null;
            $current = $current[$part];
        }
        return $current;
    }

    private function regex(string $pattern): ?string
    {
        if ($pattern === '') return null;
        if (@preg_match($pattern, '') !== false) return $pattern;
        $escapedDelimiter = str_replace('~', '\\~', $pattern);
        $regex = '~' . $escapedDelimiter . '~iu';
        return @preg_match($regex, '') === false ? null : $regex;
    }

    private function glob(string $pattern, string $value): bool
    {
        $regex = '~^' . str_replace(['\\*', '\\?'], ['.*', '.'], preg_quote($pattern, '~')) . '$~iu';
        return preg_match($regex, $value) === 1;
    }

    private function scalar(mixed $v): string
    {
        if (is_bool($v)) return $v ? 'true' : 'false';
        if ($v === null) return 'null';
        return is_scalar($v) ? (string)$v : (json_encode($v, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?: '');
    }

    private function uniquePairs(array $items): array
    {
        $seen = []; $out = [];
        foreach ($items as $item) { $key = json_encode($item, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES); if (!isset($seen[$key])) { $seen[$key] = true; $out[] = $item; } }
        return $out;
    }

    private function uniqueEntities(array $items): array
    {
        $out = [];
        foreach ($items as $item) {
            $key = strtolower((string)$item['value']);
            if (!isset($out[$key]) || (int)$item['confidence'] > (int)$out[$key]['confidence']) $out[$key] = $item;
        }
        return array_values($out);
    }

    private function text(string $path, string $fallback): string
    {
        $value = $this->getPath($this->cfg, $path);
        return is_string($value) ? $value : $fallback;
    }

    private function entityLabel(string $type, int $count): string
    {
        $labels = $this->cfg['entity_labels'][$type] ?? null;
        if (is_array($labels)) return (string)($labels[$count === 1 ? 'one' : 'many'] ?? $type);
        return is_string($labels) ? $labels : $type;
    }
}

function h(mixed $value): string { return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function renderValue(mixed $value): string {
    if (is_bool($value)) return $value ? 'true' : 'false';
    if ($value === null) return 'null';
    return is_scalar($value) ? (string)$value : (json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?: '');
}

$configFile = __DIR__ . '/data.json';
$error = null;
$result = null;
$input = '';

try {
    if (!is_file($configFile) || !is_readable($configFile)) throw new RuntimeException('data.json fehlt oder ist nicht lesbar.');
    $configRaw = file_get_contents($configFile);
    if ($configRaw === false) throw new RuntimeException('data.json konnte nicht gelesen werden.');
    $config = json_decode($configRaw, true, MAX_DEPTH, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
    if (!is_array($config)) throw new RuntimeException('data.json muss ein JSON-Objekt enthalten.');

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $input = (string)($_POST['log'] ?? '');
        $result = (new InvestigationAnalyzer($config))->analyze($input);
    }
} catch (Throwable $e) {
    $error = $e->getMessage();
}
?>
<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>IDR Investigation Analyzer</title>
<style>
:root{color-scheme:light;--bg:#ffffff;--fg:#1f2937;--muted:#6b7280;--line:#dfe3e8;--panel:#f7f8fa;--accent:#1769e0;--accent2:#0f4fb5;--header:#ffffff;--input:#ffffff;--shadow:0 8px 24px rgba(15,23,42,.07)}html[data-theme="dark"]{color-scheme:dark;--bg:#0f172a;--fg:#e5e7eb;--muted:#94a3b8;--line:#334155;--panel:#172033;--accent:#60a5fa;--accent2:#3b82f6;--header:#111827;--input:#111827;--shadow:0 10px 28px rgba(0,0,0,.26)}@media(prefers-color-scheme:dark){html:not([data-theme="light"]){color-scheme:dark;--bg:#0f172a;--fg:#e5e7eb;--muted:#94a3b8;--line:#334155;--panel:#172033;--accent:#60a5fa;--accent2:#3b82f6;--header:#111827;--input:#111827;--shadow:0 10px 28px rgba(0,0,0,.26)}}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 Arial,sans-serif}.wrap{max-width:1180px;margin:0 auto;padding:24px}.top{display:flex;align-items:center;gap:14px;border-bottom:1px solid var(--line);padding:14px 16px;background:var(--header);border-radius:8px;box-shadow:var(--shadow)}.app-icon{width:42px;height:42px;display:grid;place-items:center;border-radius:9px;background:linear-gradient(145deg,var(--accent),var(--accent2));color:#fff;flex:0 0 auto}.app-icon svg{width:25px;height:25px}.title{font-size:22px;font-weight:700}.brand{font-weight:700;letter-spacing:.08em;color:var(--accent)}.spacer{flex:1}button{border:1px solid var(--line);background:var(--panel);color:var(--fg);border-radius:6px;padding:9px 14px;cursor:pointer}.primary{background:var(--accent);border-color:var(--accent);color:#fff}textarea{width:100%;min-height:260px;margin-top:24px;padding:14px;border:1px solid var(--line);border-radius:7px;background:var(--input);color:var(--fg);font:13px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace;resize:vertical}.actions{display:flex;gap:10px;margin-top:10px}.section{margin-top:28px}.section h2{font-size:17px;margin:0 0 10px}.card{border:1px solid var(--line);border-radius:7px;background:var(--panel);padding:16px;box-shadow:var(--shadow)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}.metric{border:1px solid var(--line);border-radius:4px;padding:12px;background:var(--bg)}.label{color:var(--muted);font-size:12px}.value{font-size:18px;font-weight:700;margin-top:3px}.badge{display:inline-block;padding:3px 8px;border-radius:999px;color:#fff;font-weight:700}.item{padding:10px 0;border-bottom:1px solid var(--line)}.item:last-child{border-bottom:0}.muted{color:var(--muted)}details{margin-top:10px}summary{cursor:pointer;font-weight:700}.error{border-color:#ef4444;color:#b91c1c;white-space:pre-wrap}.kv{display:grid;grid-template-columns:minmax(180px,34%) 1fr;gap:7px 14px}.kv div{overflow-wrap:anywhere}.raw{max-height:430px;overflow:auto;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}@media(max-width:640px){.wrap{padding:14px}.top{flex-wrap:wrap}.kv{grid-template-columns:1fr}.title{width:100%}}
</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div class="app-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 4.8 6v5.4c0 4.5 2.9 7.7 7.2 9.6 4.3-1.9 7.2-5.1 7.2-9.6V6L12 3Z"/><path d="m8.8 12 2.1 2.1 4.5-4.6"/></svg></div>
    <div class="title">IDR Investigation Analyzer</div>
    <div class="brand">IDR ANALYZER</div>
    <div class="spacer"></div>
    <button type="button" id="themeToggle" aria-label="Darstellung wechseln">DUNKEL</button>
    <button type="button" id="copyLink">LINK KOPIEREN</button>
  </div>

  <form method="post" accept-charset="UTF-8">
    <textarea name="log" spellcheck="false" placeholder="Rapid7 Investigation JSON oder NDJSON einfügen"><?=h($input)?></textarea>
    <div class="actions"><button class="primary" type="submit">ANALYSIEREN</button><button type="button" id="clear">LEEREN</button></div>
  </form>

  <?php if ($error !== null): ?><div class="section card error"><?=h($error)?></div><?php endif; ?>

  <?php if ($result !== null): $a=$result['aggregate']; ?>
  <div class="section">
    <h2>Übersicht</h2>
    <div class="grid">
      <div class="metric"><div class="label">Datensätze</div><div class="value"><?=h($result['record_count'])?></div></div>
      <div class="metric"><div class="label">Format</div><div class="value"><?=h(strtoupper($result['input_format']))?></div></div>
      <div class="metric"><div class="label">Maximaler Score</div><div class="value"><?=h($a['max_score'])?></div></div>
      <div class="metric"><div class="label">Bewertung</div><div class="value"><span class="badge" style="background:<?=h($a['severity']['color'])?>"><?=h($a['severity']['label'])?></span></div></div>
    </div>
  </div>

  <?php foreach ($result['records'] as $record): ?>
  <div class="section">
    <h2>Ereignis <?=h($record['index'])?></h2>
    <div class="card">
      <div><?=h($record['summary'])?></div>
      <div class="muted" style="margin-top:6px">Score <?=h($record['score'])?> · <?=h($record['severity']['label'])?></div>
    </div>

    <?php if ($record['findings'] !== []): ?><details open><summary>Bewertung (<?=count($record['findings'])?>)</summary><div class="card"><?php foreach($record['findings'] as $f): ?><div class="item"><strong><?=h($f['title'])?></strong> <span class="muted">+<?=h($f['score'])?></span><?php if($f['description']!==''): ?><div><?=h($f['description'])?></div><?php endif; ?></div><?php endforeach; ?></div></details><?php endif; ?>

    <?php if ($record['events'] !== []): ?><details open><summary>Erkannte Ereignisse</summary><div class="card"><?php foreach($record['events'] as $e): ?><div class="item"><strong><?=h($e['title'] ?? $e['name'] ?? $e['id'])?></strong><?php if(isset($e['summary'])): ?><div><?=h($e['summary'])?></div><?php endif; ?></div><?php endforeach; ?></div></details><?php endif; ?>

    <?php if ($record['entities'] !== []): ?><details open><summary>Entitäten</summary><div class="card"><?php foreach($record['entities'] as $type=>$items): ?><div class="item"><strong><?=h($type)?></strong><div><?=h(implode(', ',array_column($items,'value')))?></div></div><?php endforeach; ?></div></details><?php endif; ?>

    <?php if ($record['timeline'] !== []): ?><details><summary>Timeline</summary><div class="card"><?php foreach($record['timeline'] as $t): ?><div class="item"><strong><?=h(renderValue($t['time']))?></strong> · <?=h($t['event'])?><div class="muted"><?=h($t['path'])?></div></div><?php endforeach; ?></div></details><?php endif; ?>

    <?php if ($record['mitre'] !== []): ?><details><summary>MITRE ATT&amp;CK</summary><div class="card"><?php foreach($record['mitre'] as $m): ?><div class="item"><strong><?=h($m['id'])?></strong><?php if(isset($m['name'])): ?> · <?=h($m['name'])?><?php endif; ?></div><?php endforeach; ?></div></details><?php endif; ?>

    <details><summary>Normalisierte Felder</summary><div class="card kv"><?php foreach($record['normalized'] as $name=>$items): ?><div><strong><?=h($name)?></strong></div><div><?=h(implode(', ',array_map(fn($x)=>renderValue($x['value']),$items)))?></div><?php endforeach; ?></div></details>
    <details><summary>Alle Rohfelder</summary><div class="card kv raw"><?php foreach($record['raw_fields'] as $path=>$value): ?><div><?=h($path)?></div><div><?=h(renderValue($value))?></div><?php endforeach; ?></div></details>
  </div>
  <?php endforeach; endif; ?>
</div>
<script>
const root=document.documentElement;const themeButton=document.getElementById('themeToggle');const storedTheme=localStorage.getItem('idr-theme');if(storedTheme){root.dataset.theme=storedTheme}function syncThemeButton(){const dark=root.dataset.theme==='dark'||(!root.dataset.theme&&matchMedia('(prefers-color-scheme: dark)').matches);themeButton.textContent=dark?'HELL':'DUNKEL'}syncThemeButton();themeButton.addEventListener('click',()=>{const dark=root.dataset.theme==='dark'||(!root.dataset.theme&&matchMedia('(prefers-color-scheme: dark)').matches);root.dataset.theme=dark?'light':'dark';localStorage.setItem('idr-theme',root.dataset.theme);syncThemeButton()});document.getElementById('copyLink').addEventListener('click',async()=>{try{await navigator.clipboard.writeText(location.href);const b=document.getElementById('copyLink');const t=b.textContent;b.textContent='KOPIERT';setTimeout(()=>b.textContent=t,1200)}catch(e){prompt('Link kopieren:',location.href)}});document.getElementById('clear').addEventListener('click',()=>{document.querySelector('textarea[name="log"]').value=''});
</script>
</body>
</html>
